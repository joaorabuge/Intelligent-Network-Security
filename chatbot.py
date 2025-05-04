# chatbot.py
import os
import openai

openai.api_key = os.getenv("OPENAI_API_KEY")

def generate_chatbot_response(query, context=None, history=None):
    """
    query:   the latest user message (string)
    context: dict with "full_network_summary" (JSON string) from Zeek logs
    history: list of prior turns in OpenAI format, e.g.
             [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
    """

    # 1) A single system prompt that covers all behavior
    system_prompt = """
    You are a network-security assistant.  You have two modes:

    1) DISCOVERY MODE
      - If the user has NOT yet given you any IP→device mappings,
        summarize only the *destination-IP anomalies*:
          • Total/normal/anomalous packet counts
          • Breakdown by attack type
          • List the top destination IPs (with counts)
        Then ask: “Please tell me what type of device each of those IPs represents.”

    2) MITIGATION MODE
      - As soon as the user supplies any mapping of IP→device (for any device, vendor or OS),
        switch to mitigation. Do NOT revert to Discovery.
      - Produce a numbered, step-by-step mitigation plan:
          Step 1 – …  
          Step 2 – …  
          etc.
        • Each step can be a CLI command, a GUI navigation, or a config-file edit.
      - If the user says “next step” or “step N”, give exactly that step.
      - If the user says “give me all commands” or “all steps”, output the entire plan at once.
      - If the user asks for “overall stats” at any time, answer with the four metrics below.
      - **After** the user tells you “I’ve done all of the mitigation steps,” immediately instruct:
          “Great. Please run a fresh network analysis now and share the updated summary so we can confirm there are no remaining attacks.”

    3) STATS YOU CAN PROVIDE
      Whenever asked for stats (e.g. “stats,” “overall stats,” “show me metrics”):
        • Total packet count  
        • Normal packet count  
        • Anomalous packet count  
        • Breakdown by attack type  
        • Top destination IPs (with counts)  
      First state: “I can provide the following stats: …” then list them, then give the numbers from the latest network summary.

    Always preserve and honor any device names or vendors the user mentions—there are no pre-defined device types. Use the full conversation history (and the injected Zeek summary) to know which mode you’re in.
    """


    # 2) Assemble the messages list
    messages = [{"role": "system", "content": system_prompt}]

    # 3) Inject the Zeek-derived network summary exactly once
    if context and context.get("full_network_summary"):
        messages.append({
            "role": "system",
            "content": "Network summary:\n" + context["full_network_summary"]
        })

    # 4) Replay the entire chat history so the model “remembers” everything
    if history:
        messages.extend(history)

    # 5) Append the latest user message
    messages.append({"role": "user", "content": query})

    # 6) Call the OpenAI API
    try:
        resp = openai.ChatCompletion.create(
            model="o4-mini",
            messages=messages
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"Error generating response: {e}"
