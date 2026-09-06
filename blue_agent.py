import os
from pydantic import BaseModel, Field
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

class SecurityAnalysis(BaseModel):
    threat_detected: bool = Field(description="True if an attack or unauthorized access pattern is detected")
    vulnerability_type: str = Field(description="e.g. IDOR, Broken Object Level Authorization, None")
    reasoning: str = Field(description="Brief explanation of why this was or was not flagged")
    remediation_suggestion: str = Field(description="Actionable fix for the backend code")

llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0)
structured_llm = llm.with_structured_output(SecurityAnalysis)

system_prompt = """You are an autonomous Blue Team AI Detection Engine.
Your task is to analyze HTTP traffic and server logs from a web application, detect attacks (especially OWASP Top 10 like IDOR/BOLA), and recommend defensive mitigations.
Be precise, factual, and strict."""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", """Analyze the following request/response transaction:
Target URL: {url}
Method: {method}
Status Code: {status_code}
Response Body: {response_body}
Server Log: {server_log}
""")
])

def run_blue_detection(url: str, method: str, status_code: int, response_body: str, server_log: str) -> SecurityAnalysis:
    chain = prompt_template | structured_llm
    result = chain.invoke({
        "url": url,
        "method": method,
        "status_code": status_code,
        "response_body": response_body,
        "server_log": server_log
    })
    return result

if __name__ == "__main__":
    test_result = run_blue_detection(
        url="http://127.0.0.1:8001/api/user/999",
        method="GET",
        status_code=200,
        response_body='{"id":"999","name":"Admin","role":"admin","secret_note":"Super secret admin token: xyz123"}',
        server_log="Incoming request from 127.0.0.1 targeting user_id: 999"
    )
    print("--- Blue Agent Analysis Result ---")
    print(f"Threat Detected: {test_result.threat_detected}")
    print(f"Vulnerability Type: {test_result.vulnerability_type}")
    print(f"Reasoning: {test_result.reasoning}")
    print(f"Remediation: {test_result.remediation_suggestion}")