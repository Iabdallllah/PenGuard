from pydantic import BaseModel, Field
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
import requests

class AttackPlan(BaseModel):
    vulnerability_target: str = Field(description="The vulnerability type being tested, e.g., IDOR")
    target_endpoint: str = Field(description="The specific endpoint URL to target")
    http_method: str = Field(description="HTTP method to use (GET, POST, etc.)")
    hypothesis: str = Field(description="Why this request is expected to expose sensitive data or bypass controls")

llm = ChatGroq(model_name="openai/gpt-oss-20b", temperature=0.2)
structured_llm = llm.with_structured_output(AttackPlan)

system_prompt = """You are an autonomous Red Team Security Agent.
Your objective is to conduct automated penetration testing against web applications mapped to the OWASP Top 10.
Analyze the target URL and context to formulate a high-probability attack or audit payload (e.g., IDOR/BOLA user enumeration).
Provide strict structured output."""

prompt_template = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", """Target Base URL: {base_url}
Known endpoints or context:
- The app has an endpoint at /api/user/{{user_id}}
- Standard user ID observed: 101

Generate an attack plan to verify if unauthorized/administrative records can be accessed.""")
])

def run_red_attack(base_url: str):
    chain = prompt_template | structured_llm
    plan = chain.invoke({"base_url": base_url})
    
    print("--- Red Agent Attack Plan ---")
    print(f"Target: {plan.vulnerability_target}")
    print(f"Endpoint: {plan.target_endpoint}")
    print(f"Hypothesis: {plan.hypothesis}")
    
    response = requests.request(
        method=plan.http_method,
        url=plan.target_endpoint
    )
    
    return plan, response

if __name__ == "__main__":
    plan, resp = run_red_attack("http://127.0.0.1:8001")
    print("\n--- Execution Result ---")
    print(f"Status Code: {resp.status_code}")
    print(f"Response Body: {resp.text}")