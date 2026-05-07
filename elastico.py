# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax import swing
from javax.swing import JPanel, JLabel, JTextField, JButton, JToggleButton, JTabbedPane, JEditorPane, JScrollPane, JComboBox
from java.awt import GridLayout, BorderLayout, FlowLayout
from threading import Thread
from Queue import Queue
import json
import datetime
import urllib2
import time


ELASTIC_HOST = "localhost"
ELASTIC_PORT = "9200"
ELASTIC_INDEX = "burplogs_cliente_x"
ELASTIC_URL = "http://"+ELASTIC_HOST+":"+ELASTIC_PORT+"/"+ELASTIC_INDEX+"/_doc"

SPLUNK_HOST  = "localhost"
SPLUNK_PORT  = "8088"
SPLUNK_TOKEN = ""
SPLUNK_INDEX = "main"
SPLUNK_URL   = "http://" + SPLUNK_HOST + ":" + SPLUNK_PORT + "/services/collector/event"

SELECTED_BACKEND = "Elasticsearch"

ELASTIC_HELP = """
<html>
<body style='font-family: Arial, sans-serif; margin: 30px 40px; background-color: #1e1e1e; color: #d4d4d4;'>

<p style='font-size:13px;'>
  <a href='#en' style='color:#e8912d;'>English</a> &nbsp;|&nbsp;
  <a href='#pt' style='color:#e8912d;'>Portugues</a>
</p>

<hr style='border-color:#333;'/>

<a name='en'></a>
<h1 style='color: #e8912d; border-bottom: 2px solid #e8912d; padding-bottom: 8px;'>Elastico (EN-US)</h1>
<p>Burp Suite extension to index HTTP traffic directly into Elasticsearch and/or Splunk, enabling analysis and visualization in Kibana or Splunk dashboards.</p>
<p>Source code: <a href='https://github.com/imgodes/elastico' style='color: #e8912d;'>github.com/imgodes/elastico</a></p>

<h2 style='color: #e8912d; margin-top: 30px;'>How it works</h2>
<p>The extension intercepts all traffic passing through Burp Proxy and sends each request/response cycle as a JSON document to Elasticsearch and/or Splunk HEC.</p>
<p>Full flow:</p>
<ol style='line-height: 2;'>
    <li><b>Interception:</b> Burp calls <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>processHttpMessage</code> on every HTTP response passing through the Proxy.</li>
    <li><b>Extraction:</b> Request and response data are extracted from <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>messageInfo</code> using Burp API helpers.</li>
    <li><b>Serialization:</b> Data is assembled into a hierarchical JSON document with fields like host, method, URL, headers, and body.</li>
    <li><b>Queue:</b> The document is pushed into an internal <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>Queue</code> without blocking the Proxy.</li>
    <li><b>Dispatch:</b> A worker thread consumes the queue and sends each document to the selected backend(s) via HTTP POST.</li>
    <li><b>Visualization:</b> Documents are available in Kibana or Splunk for queries, dashboards, and traffic analysis.</li>
</ol>

<h2 style='color: #e8912d; margin-top: 30px;'>Elasticsearch Configuration</h2>
<p>In the <b>Settings</b> tab, configure:</p>
<ul style='line-height: 2;'>
    <li><b>Host:</b> Elasticsearch address (default: localhost)</li>
    <li><b>Port:</b> Elasticsearch port (default: 9200)</li>
    <li><b>Index:</b> Index name where documents will be stored (must be lowercase)</li>
</ul>
<p>Click <b>Save</b> to apply. Subsequent requests will be indexed using the new configuration.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Splunk HEC</h2>
<p>To send traffic to Splunk, configure the Splunk HEC fields in the Settings tab:</p>
<ul style='line-height: 2;'>
    <li><b>Splunk Host:</b> Splunk instance address (default: localhost)</li>
    <li><b>Splunk Port:</b> HEC port (default: 8088)</li>
    <li><b>Splunk Token:</b> HEC token — obtain it at Settings &gt; Data Inputs &gt; HTTP Event Collector in Splunk Web</li>
    <li><b>Splunk Index:</b> Destination index (default: main)</li>
    <li><b>Backend:</b> Choose Elasticsearch, Splunk, or Both to control where logs are sent</li>
</ul>
<p>To obtain a HEC token: in Splunk Web, go to <b>Settings &gt; Data Inputs &gt; HTTP Event Collector</b>, click <b>New Token</b>, and copy the generated token value into the Splunk Token field.</p>
<p><b>SSL note:</b> Splunk HEC enables SSL by default. This extension sends plain HTTP, so you must disable SSL in Global Settings before using it. After disabling, restart Splunk and verify the endpoint with:</p>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:12px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
curl http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk &lt;your-token&gt;" \
  -d '{"event": "test"}'
</pre>
<p>Expected response: <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>{"text":"Success","code":0}</code></p>

<h2 style='color: #e8912d; margin-top: 30px;'>Live Logging</h2>
<p>Live Logging is <b>disabled by default</b>. Toggle it in the Settings tab to start or stop real-time indexing of traffic passing through Burp Proxy.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Send bulk logs</h2>
<p>Click <b>Send bulk logs</b> to export the entire Burp Proxy history to the selected backend(s) in one shot. This runs in the background and does not require Live Logging to be enabled.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Deploy ELK Stack</h2>
<p>Recommended setup using Docker. Official docs:</p>
<p><a href='https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic' style='color: #e8912d;'>elastic.co/docs - Install Elasticsearch with Docker</a></p>
<p>For local lab use, run Elasticsearch with security disabled:</p>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:16px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
docker run --name es01 --net elastic -p 9200:9200 -m 4GB \
  -e "xpack.security.enabled=false" \
  -e "xpack.security.http.ssl.enabled=false" \
  -e "discovery.type=single-node" \
  -v elasticsearch-data:/usr/share/elasticsearch/data \
  -d docker.elastic.co/elasticsearch/elasticsearch:9.4.0
</pre>

<h2 style='color: #e8912d; margin-top: 30px;'>Document structure</h2>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:16px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
{
  "timestamp": "2026-05-07T00:00:00",
  "host": "example.com",
  "port": 443,
  "protocol": "https",
  "http": {
    "request": {
      "method": "POST",
      "url": "https://example.com/api/login",
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

<hr style='border-color:#333; margin-top:40px;'/>

<a name='pt'></a>
<h1 style='color: #e8912d; border-bottom: 2px solid #e8912d; padding-bottom: 8px;'>Elastico (PT-BR)</h1>
<p>Extensao do Burp Suite para indexar trafego HTTP diretamente no Elasticsearch e/ou Splunk, permitindo analise e visualizacao no Kibana ou dashboards do Splunk.</p>
<p>Codigo fonte: <a href='https://github.com/imgodes/elastico' style='color: #e8912d;'>github.com/imgodes/elastico</a></p>

<h2 style='color: #e8912d; margin-top: 30px;'>Como funciona</h2>
<p>A extensao intercepta todo o trafego que passa pelo Proxy do Burp e envia cada ciclo request/response como um documento JSON para o Elasticsearch e/ou Splunk HEC.</p>
<p>O fluxo completo:</p>
<ol style='line-height: 2;'>
    <li><b>Interceptacao:</b> o Burp chama <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>processHttpMessage</code> a cada resposta HTTP que passa pelo Proxy.</li>
    <li><b>Extracao:</b> os dados da request e response sao extraidos do <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>messageInfo</code> usando os helpers da API do Burp.</li>
    <li><b>Serializacao:</b> os dados sao montados em um documento JSON hierarquico com campos como host, metodo, URL, headers e body.</li>
    <li><b>Fila:</b> o documento e empurrado para uma fila interna (<code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>Queue</code>) sem bloquear o Proxy.</li>
    <li><b>Despacho:</b> uma thread worker consome a fila e envia cada documento para o(s) backend(s) selecionado(s) via HTTP POST.</li>
    <li><b>Visualizacao:</b> os documentos ficam disponiveis no Kibana ou Splunk para queries, dashboards e analise do trafego capturado.</li>
</ol>

<h2 style='color: #e8912d; margin-top: 30px;'>Configuracao do Elasticsearch</h2>
<p>Na aba <b>Settings</b>, configure:</p>
<ul style='line-height: 2;'>
    <li><b>Host:</b> endereco do Elasticsearch (default: localhost)</li>
    <li><b>Port:</b> porta do Elasticsearch (default: 9200)</li>
    <li><b>Index:</b> nome do indice onde os documentos serao armazenados (deve ser lowercase)</li>
</ul>
<p>Clique em <b>Salvar</b> para aplicar. As proximas requests ja serao indexadas com a nova configuracao.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Splunk HEC</h2>
<p>Para enviar o trafego ao Splunk, configure os campos Splunk HEC na aba Settings:</p>
<ul style='line-height: 2;'>
    <li><b>Splunk Host:</b> endereco da instancia Splunk (default: localhost)</li>
    <li><b>Splunk Port:</b> porta do HEC (default: 8088)</li>
    <li><b>Splunk Token:</b> token HEC - obtenha em Settings &gt; Data Inputs &gt; HTTP Event Collector no Splunk Web</li>
    <li><b>Splunk Index:</b> indice de destino (default: main)</li>
    <li><b>Backend:</b> escolha Elasticsearch, Splunk ou Both para controlar para onde os logs serao enviados</li>
</ul>
<p>Para obter um token HEC: no Splunk Web, va em <b>Settings &gt; Data Inputs &gt; HTTP Event Collector</b>, clique em <b>New Token</b> e copie o valor gerado para o campo Splunk Token.</p>
<p><b>Nota sobre SSL:</b> o HEC do Splunk habilita SSL por padrao. Esta extensao envia HTTP puro, entao e necessario desabilitar o SSL nas Global Settings antes de usar. Apos desabilitar, reinicie o Splunk e verifique o endpoint com:</p>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:12px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
curl http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk &lt;seu-token&gt;" \
  -d '{"event": "test"}'
</pre>
<p>Resposta esperada: <code style='background:#2d2d2d; padding:2px 6px; border-radius:3px;'>{"text":"Success","code":0}</code></p>

<h2 style='color: #e8912d; margin-top: 30px;'>Live Logging</h2>
<p>O Live Logging e <b>desabilitado por padrao</b>. Use o toggle na aba Settings para ligar ou desligar a indexacao em tempo real do trafego que passa pelo Burp Proxy.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Send bulk logs</h2>
<p>Clique em <b>Send bulk logs</b> para exportar todo o historico do Proxy do Burp para o(s) backend(s) selecionado(s) de uma vez. Roda em background e nao exige que o Live Logging esteja ativado.</p>

<h2 style='color: #e8912d; margin-top: 30px;'>Deploy do ELK</h2>
<p>Recomenda-se subir o Elasticsearch e Kibana via Docker. Instrucoes oficiais:</p>
<p><a href='https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic' style='color: #e8912d;'>elastic.co/docs - Install Elasticsearch with Docker</a></p>
<p>Importante: suba o Elasticsearch com seguranca desabilitada para uso em lab local:</p>
<pre style='background:#2d2d2d; color:#d4d4d4; padding:16px; border-radius:6px; border-left: 3px solid #e8912d; overflow:auto;'>
docker run --name es01 --net elastic -p 9200:9200 -m 4GB \
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

        self.live_logging = False
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

        settingsWrapper = JPanel(BorderLayout())

        formPanel = JPanel(GridLayout(12, 2, 5, 5))

        formPanel.add(JLabel("Host:"))
        self.hostField = JTextField(ELASTIC_HOST, 20)
        formPanel.add(self.hostField)

        formPanel.add(JLabel("Port:"))
        self.portField = JTextField(ELASTIC_PORT, 20)
        formPanel.add(self.portField)

        formPanel.add(JLabel("Index:"))
        self.indexField = JTextField(ELASTIC_INDEX, 20)
        formPanel.add(self.indexField)

        formPanel.add(JLabel(u"── Splunk HEC ──"))
        formPanel.add(JLabel(""))

        formPanel.add(JLabel("Splunk Host:"))
        self.splunkHostField = JTextField(SPLUNK_HOST, 20)
        formPanel.add(self.splunkHostField)

        formPanel.add(JLabel("Splunk Port:"))
        self.splunkPortField = JTextField(SPLUNK_PORT, 20)
        formPanel.add(self.splunkPortField)

        formPanel.add(JLabel("Splunk Token:"))
        self.splunkTokenField = JTextField(SPLUNK_TOKEN, 20)
        formPanel.add(self.splunkTokenField)

        formPanel.add(JLabel("Splunk Index:"))
        self.splunkIndexField = JTextField(SPLUNK_INDEX, 20)
        formPanel.add(self.splunkIndexField)

        formPanel.add(JLabel("Backend:"))
        self.backendCombo = JComboBox(["Elasticsearch", "Splunk", "Both"])
        formPanel.add(self.backendCombo)

        formPanel.add(JLabel(""))
        saveButton = JButton("Salvar", actionPerformed=self.saveConfig)
        formPanel.add(saveButton)

        formPanel.add(JLabel("Live Logging:"))
        self.liveLoggingBtn = JToggleButton("Desabilitado", actionPerformed=self.toggleLiveLogging)
        formPanel.add(self.liveLoggingBtn)

        formPanel.add(JLabel(""))
        bulkBtn = JButton("Send bulk logs", actionPerformed=self.sendBulkLogs)
        formPanel.add(bulkBtn)

        settingsWrapper.add(formPanel, BorderLayout.NORTH)
        self.tabbedPane.addTab("Settings", settingsWrapper)

        helpPanel = JEditorPane("text/html", ELASTIC_HELP)
        helpPanel.setEditable(False)
        self.tabbedPane.addTab("Help", JScrollPane(helpPanel))

    def saveConfig(self, event):
        global ELASTIC_HOST, ELASTIC_PORT, ELASTIC_INDEX, ELASTIC_URL
        global SPLUNK_HOST, SPLUNK_PORT, SPLUNK_TOKEN, SPLUNK_INDEX, SPLUNK_URL, SELECTED_BACKEND
        ELASTIC_HOST = self.hostField.getText()
        ELASTIC_PORT = self.portField.getText()
        ELASTIC_INDEX = self.indexField.getText()
        ELASTIC_URL = "http://"+ELASTIC_HOST+":"+ELASTIC_PORT+"/"+ELASTIC_INDEX+"/_doc"
        SPLUNK_HOST = self.splunkHostField.getText()
        SPLUNK_PORT = self.splunkPortField.getText()
        SPLUNK_TOKEN = self.splunkTokenField.getText()
        SPLUNK_INDEX = self.splunkIndexField.getText()
        SPLUNK_URL = "http://" + SPLUNK_HOST + ":" + SPLUNK_PORT + "/services/collector/event"
        SELECTED_BACKEND = str(self.backendCombo.getSelectedItem())
        print("[*] Config atualizada: Elastic=%s | Splunk=%s | Backend=%s" % (ELASTIC_URL, SPLUNK_URL, SELECTED_BACKEND))

    def toggleLiveLogging(self, event):
        self.live_logging = self.liveLoggingBtn.isSelected()
        if self.live_logging:
            self.liveLoggingBtn.setText("Habilitado")
            print("[*] Live Logging habilitado.")
        else:
            self.liveLoggingBtn.setText("Desabilitado")
            print("[*] Live Logging desabilitado.")

    def sendBulkLogs(self, event):
        def run():
            history = self.callbacks.getProxyHistory()
            total = len(history)
            print("[*] Iniciando bulk export: %d itens." % total)
            sent = 0
            for item in history:
                try:
                    responseRaw = item.getResponse()
                    if responseRaw is None:
                        continue
                    requestRaw = item.getRequest()
                    requestInfo = self._helpers.analyzeRequest(item)
                    responseInfo = self._helpers.analyzeResponse(responseRaw)
                    jsonLogLine = self.buildJson(item, requestInfo, responseInfo, requestRaw, responseRaw)
                    self.queue.put(jsonLogLine)
                    sent += 1
                except Exception as e:
                    print("[!] Erro ao processar item: %s" % str(e))
            print("[*] Bulk export: %d/%d itens enfileirados." % (sent, total))
        Thread(target=run).start()

    def getTabCaption(self):
        return("Elastico")

    def getUiComponent(self):
        return self.tab

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and self.live_logging:
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
            if SELECTED_BACKEND == "Splunk":
                self.sentToSplunk(nextJsonLine)
            elif SELECTED_BACKEND == "Both":
                self.sentToElastic(nextJsonLine)
                self.sentToSplunk(nextJsonLine)
            else:
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

    def sentToSplunk(self, logLine):
        if not SPLUNK_TOKEN:
            print("[!] Splunk HEC token nao configurado. Skipping.")
            return
        try:
            envelope = {
                "time": time.time(),
                "sourcetype": "_json",
                "index": SPLUNK_INDEX,
                "event": logLine
            }
            data = json.dumps(envelope)
            req = urllib2.Request(
                SPLUNK_URL,
                data,
                {
                    "Content-Type": "application/json",
                    "Authorization": "Splunk " + SPLUNK_TOKEN
                }
            )
            urllib2.urlopen(req, timeout=5)
            print("[+] Splunk HEC: %s %s -> %d" % (
                logLine["http"]["request"]["method"],
                logLine["http"]["request"]["url"],
                logLine["http"]["response"]["status"]
            ))
        except urllib2.HTTPError as e:
            print("[!] Splunk HTTP Error %d: %s" % (e.code, e.read()))
        except Exception as e:
            print("[!] Splunk Erro: %s" % str(e))
