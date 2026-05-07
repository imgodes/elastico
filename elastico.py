from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax import swing
from javax.swing import JPanel, JLabel, JTextField, JButton, JTabbedPane, JEditorPane, JScrollPane
from java.awt import GridLayout, BorderLayout, FlowLayout
from threading import Thread
from Queue import Queue
import json
import datetime
import urllib2


ELASTIC_HOST = "localhost"
ELASTIC_PORT = "9200"
ELASTIC_INDEX = "burplogs_cliente_x"
ELASTIC_URL = "http://"+ELASTIC_HOST+":"+ELASTIC_PORT+"/"+ELASTIC_INDEX+"/_doc"

ELASTIC_HELP = """
<html>
<body style='font-family: Arial, sans-serif; margin: 30px 40px; background-color: #1e1e1e; color: #d4d4d4;'>

<h1 style='color: #e8912d; border-bottom: 2px solid #e8912d; padding-bottom: 8px;'>Elastico</h1>
<p>Extensao do Burp Suite para indexar trafego HTTP diretamente no Elasticsearch, permitindo analise e visualizacao no Kibana.</p>
<p>Codigo fonte: <a href='https://github.com/imgodes/elastico' style='color: #e8912d;'>github.com/imgodes/elastico</a></p>

<h2 style='color: #e8912d; margin-top: 30px;'>Como funciona</h2>
<p>A extensao intercepta todo o trafego que passa pelo Proxy do Burp e envia cada ciclo request/response como um documento JSON para o Elasticsearch.</p>
<p>O fluxo completo:</p>
<ol style='line-height: 2;'>
    <li><b>Interceptacao:</b> o Burp chama <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>processHttpMessage</code> a cada resposta HTTP que passa pelo Proxy.</li>
    <li><b>Extracao:</b> os dados da request e response sao extraidos do <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>messageInfo</code> usando os helpers da API do Burp.</li>
    <li><b>Serializacao:</b> os dados sao montados em um documento JSON hierarquico com campos como host, metodo, URL, headers e body.</li>
    <li><b>Fila:</b> o documento e empurrado para uma fila interna (<code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>Queue</code>) sem bloquear o Proxy.</li>
    <li><b>Indexacao:</b> uma thread worker consome a fila em paralelo e envia cada documento para o Elasticsearch via HTTP POST.</li>
    <li><b>Visualizacao:</b> os documentos ficam disponiveis no Kibana para queries, dashboards e analise do trafego capturado.</li>
</ol>

<h2 style='color: #e8912d; margin-top: 30px;'>Configuracao</h2>
<p>Na aba <b>Settings</b>, configure:</p>
<ul style='line-height: 2;'>
    <li><b>Host:</b> endereco do Elasticsearch (default: localhost)</li>
    <li><b>Port:</b> porta do Elasticsearch (default: 9200)</li>
    <li><b>Index:</b> nome do indice onde os documentos serao armazenados (deve ser lowercase)</li>
</ul>
<p>Clique em <b>Salvar</b> para aplicar. As proximas requests ja serao indexadas com a nova configuracao.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Deploy do ELK</h2>
<p>Recomenda-se subir o Elasticsearch e Kibana via Docker. Instrucoes oficiais:</p>
<p><a href='https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic' style='color: #e8912d;'>elastic.co/docs - Install Elasticsearch with Docker</a></p>
<p>Importante: suba o Elasticsearch com seguranca desabilitada para uso em lab local:</p>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:16px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
docker run --name es01 --net elastic -p 9200:9200 -m 2GB \
  -e "xpack.security.enabled=false" \
  -e "xpack.security.http.ssl.enabled=false" \
  -e "discovery.type=single-node" \
  -v elasticsearch-data:/usr/share/elasticsearch/data \
  -d docker.elastic.co/elasticsearch/elasticsearch:9.4.0
</pre>

<h2 style='color: #e8912d; margin-top: 30px;'>Estrutura do documento indexado</h2>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:16px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
{
  "timestamp": "2026-05-07T00:00:00",
  "host": "exemplo.com",
  "port": 443,
  "protocol": "https",
  "http": {
    "request": {
      "method": "POST",
      "url": "https://exemplo.com/api/login",
      "length": 312,
      "headers": { "Content-Type": "application/json" },
      "body": "{...}"
    },
    "response": {
      "status": 200,
      "length": 1024,
      "headers": { "Content-Type": "application/json" },
      "body": "{...}"
    }
  }
}
</pre>

</body>
</html>
"""

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Elastico")
        callbacks.registerHttpListener(self)
        self._helpers = callbacks.getHelpers()

        self.initGui()
        self.callbacks.addSuiteTab(self)
        print("[*] Elastic Exporter carregado.")

        self.queue = Queue()
        self.worker = Thread(target=self.processQueue)
        self.worker.setDaemon(True)
        self.worker.start()
        
    def initGui(self):
        self.tab = JPanel(BorderLayout())

        self.tabbedPane = JTabbedPane()
        self.tab.add(self.tabbedPane, BorderLayout.CENTER)

        # Painel externo que segura o form no topo
        settingsWrapper = JPanel(BorderLayout())

        # Form compacto
        formPanel = JPanel(GridLayout(4, 2, 5, 5))

        formPanel.add(JLabel("Host:"))
        self.hostField = JTextField(ELASTIC_HOST, 20)
        formPanel.add(self.hostField)

        formPanel.add(JLabel("Port:"))
        self.portField = JTextField(ELASTIC_PORT, 20)
        formPanel.add(self.portField)

        formPanel.add(JLabel("Index:"))
        self.indexField = JTextField(ELASTIC_INDEX, 20)
        formPanel.add(self.indexField)

        formPanel.add(JLabel(""))
        saveButton = JButton("Salvar", actionPerformed=self.saveConfig)
        formPanel.add(saveButton)

        settingsWrapper.add(formPanel, BorderLayout.NORTH)
        self.tabbedPane.addTab("Settings", settingsWrapper)

        helpWrapper = JPanel(BorderLayout())
        
        helpPanel =  JEditorPane("text/html", ELASTIC_HELP)
        helpPanel.setEditable(False)
        self.tabbedPane.addTab("Help", JScrollPane(helpPanel))
        
    def saveConfig(self, event):
        global ELASTIC_HOST, ELASTIC_PORT, ELASTIC_INDEX, ELASTIC_URL
        ELASTIC_HOST = self.hostField.getText()
        ELASTIC_PORT = self.portField.getText()
        ELASTIC_INDEX = self.indexField.getText()
        ELASTIC_URL = "http://"+ELASTIC_HOST+":"+ELASTIC_PORT+"/"+ELASTIC_INDEX+"/_doc"
        print "[*] Config atualizada: %s" % ELASTIC_URL

    def getTabCaption(self):
        return("Elastico")
    
    def getUiComponent(self):
        return self.tab
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            requestRaw = messageInfo.getRequest()
            responseRaw = messageInfo.getResponse()
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            responseInfo = self._helpers.analyzeResponse(responseRaw)
            jsonLogLine = self.buildJson(messageInfo, requestInfo, responseInfo, requestRaw, responseRaw)
            self.queue.put(jsonLogLine)

    def buildJson(self, messageInfo, requestInfo, responseInfo, requestRaw, responseRaw):
        timestamp = datetime.datetime.utcnow().isoformat()
        host = messageInfo.getHttpService().getHost()
        port = messageInfo.getHttpService().getPort()
        protocol = messageInfo.getHttpService().getProtocol()
        method = requestInfo.getMethod()
        url = str(requestInfo.getUrl())
        statusCode = responseInfo.getStatusCode()
        requestLength = len(requestRaw)
        responseLength = len(responseRaw)
        requestHeaders = self.buildHeadersDict(requestInfo)
        responseHeaders = self.buildHeadersDict(responseInfo)
        requestBody = self.buildBodyString(requestRaw, requestInfo)
        responseBody = self.buildBodyString(responseRaw, responseInfo)
        return {
            "timestamp": timestamp,
            "http": {
                "request": {
                    "method": method,
                    "url": url,
                    "length": requestLength,
                    "headers": requestHeaders,
                    "body": requestBody
                },
                "response": {
                    "status": statusCode,
                    "length": responseLength,
                    "headers": responseHeaders,
                    "body": responseBody
                }
            },
            "host": host,
            "port": port,
            "protocol": protocol
        }

    def buildHeadersDict(self, info):
        headers_dict = {}
        for header in info.getHeaders():
            parts = header.split(':', 1)
            if len(parts) > 1:
                headers_dict[parts[0].strip()] = parts[1].strip()
        return headers_dict

    def buildBodyString(self, rawData, info):
        offset = info.getBodyOffset()
        bodyBytes = rawData[offset:]
        try:
            body = self._helpers.bytesToString(bodyBytes)
            json.loads(body)
            return body
        except:
            return self._helpers.bytesToString(bodyBytes).encode('utf-8', errors='replace').decode('utf-8')

    def processQueue(self):
        while True:
            nextJsonLine = self.queue.get()
            self.sentToElastic(nextJsonLine)
            self.queue.task_done()

    def sentToElastic(self, logLine):
        try:
            data = json.dumps(logLine)
            req = urllib2.Request(
                ELASTIC_URL,
                data,
                {"Content-Type": "application/json"}
            )
            urllib2.urlopen(req, timeout=5)
            print("[+] Log Indexado: %s %s -> %d" % (
                logLine["http"]["request"]["method"],
                logLine["http"]["request"]["url"],
                logLine["http"]["response"]["status"]
            ))
        except urllib2.HTTPError as e:
            print("[!] HTTP Error %d: %s" % (e.code, e.read()))
        except Exception as e:
            print("[!] Erro: %s" % str(e))