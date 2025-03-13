# chatbot.py
import os
import openai

openai.api_key = os.getenv("OPENAI_API_KEY")

def generate_chatbot_response(query, context=None):
    """
    Generates a chatbot response using the regular o3-mini model.
    
    When the query is related to network security or mitigation:
      - If the network summary indicates anomalies, the assistant should provide a detailed summary,
        listing the suspicious IP addresses (with packet counts) associated with the requested attack type.
      - Then, ask the user to specify the type of device for each suspicious IP (e.g., workstation, server, IoT device, router).
      - Once the user supplies the device types, provide one comprehensive, detailed, step-by-step mitigation plan tailored
        to those devices.
      - If the user requests overall network statistics, always include a detailed summary, even if no attack is detected.
    
    Parameters:
      - query: The user's question.
      - context: Optional dictionary with detailed network context data.
      
    Returns:
      A string containing the generated response.
    """
    # Build context text if provided.
    context_text = ""
    if context:
        # Here we assume context is a dictionary containing key statistics
        # (e.g., overall stats, suspicious IPs and counts, attack type, etc.)
        context_items = []
        for key, value in context.items():
            # If the value is a JSON string or a dict, format it nicely.
            if isinstance(value, dict):
                # Create a multi-line string for dict values.
                sub_items = "\n".join([f"  - {k}: {v}" for k, v in value.items()])
                context_items.append(f"{key}:\n{sub_items}")
            else:
                context_items.append(f"{key}: {value}")
        context_text = "Network context:\n" + "\n".join(context_items) + "\n"
    
    # Build the full prompt.
    prompt = f"{context_text}User: {query}\n\n###\n\n"
    
    # Revised system instructions to guide conversation flow:
    system_message = (
        "You are a network security assistant. Your task is to help users understand and mitigate network attacks "
        "based on the provided network summary context."
    )
    
    try:
        response = openai.ChatCompletion.create(
            model="o3-mini",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]
        )
        answer = response['choices'][0]['message']['content'].strip()
        return answer
    except Exception as e:
        return f"Error generating response: {e}"
