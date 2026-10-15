import json
from elasticsearch import Elasticsearch
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()
es = Elasticsearch("https://your-es-host:9200", api_key="ES_API_KEY", verify_certs=False)
qwen = OpenAI(base_url="https://llm.gameguild.gg/v1", api_key=os.getenv("QWEN_API_KEY"))

# --- Stage 1: parse/normalize in code, no model ---
def parse_alert(doc):
    return {
        "rule": doc.get("kibana.alert.rule.name"),
        "host": doc.get("host", {}).get("name"),
        "user": doc.get("user", {}).get("name"),
        "process": doc.get("process", {}).get("command_line"),
        "parent": doc.get("process", {}).get("parent", {}).get("command_line"),
        "severity": doc.get("kibana.alert.severity"),
        "timestamp": doc.get("@timestamp"),
    }

resp = es.search(index=".alerts-security.alerts-*", size=100,
                 query={"range": {"@timestamp": {"gte": "now-1h"}}},
                 sort=[{"@timestamp": "desc"}])
parsed = [parse_alert(h["_source"]) for h in resp["hits"]["hits"]]

# --- Stage 2: batch the clean JSON to the model ---
def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

for batch in chunk(parsed, 10):          # tune 10 upward as quality allows
    completion = qwen.chat.completions.create(
        model="qwen",
        messages=[
            {"role": "system", "content":
             "You are a SOC analyst. For each alert in the JSON array, return a JSON "
             "object with: rule, mitre_technique, severity_1_5, one_line_summary. "
             "Respond with a JSON array only, no prose."},
            {"role": "user", "content": json.dumps(batch)},
        ],
        temperature=0,
    )
    print(completion.choices[0].message.content)