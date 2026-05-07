# Elastico

Extensão do Burp Suite para indexar tráfego HTTP diretamente no Elasticsearch, permitindo análise e visualização no Kibana.

## Como funciona

A extensão intercepta todo o tráfego que passa pelo Proxy do Burp e envia cada ciclo request/response como um documento JSON para o Elasticsearch.

O fluxo completo:

1. **Interceptação:** o Burp chama `processHttpMessage` a cada resposta HTTP que passa pelo Proxy.
2. **Extração:** os dados da request e response são extraídos do `messageInfo` usando os helpers da API do Burp.
3. **Serialização:** os dados são montados em um documento JSON hierárquico com campos como host, método, URL, headers e body.
4. **Fila:** o documento é empurrado para uma fila interna (`Queue`) sem bloquear o Proxy.
5. **Indexação:** uma thread worker consome a fila em paralelo e envia cada documento para o Elasticsearch via HTTP POST.
6. **Visualização:** os documentos ficam disponíveis no Kibana para queries, dashboards e análise do tráfego capturado.

```
Burp Proxy --> processHttpMessage --> Queue --> worker thread --> Elasticsearch --> Kibana
```

## Requisitos

- Burp Suite (Community ou Pro)
- Jython Standalone JAR: https://www.jython.org/download
- Elasticsearch + Kibana (ver seção Deploy)

## Instalação

1. No Burp, vá em **Extensions > Options > Python Environment** e aponte para o JAR do Jython.
2. Vá em **Extensions > Add**, selecione o tipo **Python** e carregue o arquivo `elastico.py`.
3. A aba **Elastico** vai aparecer no Burp com as abas **Settings** e **Help**.

## Configuração

Na aba **Settings**, configure:

- **Host:** endereço do Elasticsearch (default: `localhost`)
- **Port:** porta do Elasticsearch (default: `9200`)
- **Index:** nome do índice onde os documentos serão armazenados (deve ser lowercase)

Clique em **Salvar** para aplicar. As próximas requests já serão indexadas com a nova configuração.

## Deploy do ELK

Recomenda-se subir o Elasticsearch e Kibana via Docker. Instruções oficiais:
https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic

Para uso em lab local, suba o Elasticsearch com segurança desabilitada:

```bash
docker network create elastic

docker run --name es01 --net elastic -p 9200:9200 -m 4GB \
  -e "xpack.security.enabled=false" \
  -e "xpack.security.http.ssl.enabled=false" \
  -e "discovery.type=single-node" \
  -v elasticsearch-data:/usr/share/elasticsearch/data \
  -d docker.elastic.co/elasticsearch/elasticsearch:9.4.0

docker run --name kib01 --net elastic -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://es01:9200" \
  -d docker.elastic.co/kibana/kibana:9.4.0
```

Acesse o Kibana em `http://localhost:5601`.

## Estrutura do documento indexado

```json
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
      "headers": {
        "Content-Type": "application/json"
      },
      "body": "{...}"
    },
    "response": {
      "status": 200,
      "length": 1024,
      "headers": {
        "Content-Type": "application/json"
      },
      "body": "{...}"
    }
  }
}
```

## Verificando a indexação

```bash
# Contagem de documentos no índice
curl -s http://localhost:9200/<seu-index>/_count

# Últimos documentos indexados
curl -s "http://localhost:9200/<seu-index>/_search?size=3&sort=_id:desc"
```

## Licença

MIT