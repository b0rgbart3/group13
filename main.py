import requests
import os
import openai
import streamlit as st
from dotenv import load_dotenv
import pandas as pd
from agent import run_agent

response = requests.get("http://localhost:8000/logs")
logs = response.json()

for log in logs:
    print(log)

# Streamlit UI
def main():
    st.title("🤖 AI Security Log Monitor")
    st.markdown("**Step-by-step autonomous processing** with real data and transparent decision making")
    
    # Initialize session state
    if 'processed_tickets' not in st.session_state:
        st.session_state.processed_tickets = []

      # Sidebar
    with st.sidebar:
        st.header("🔧 Configuration")
        
        # API Key
        api_key = st.text_input("OpenRouter API Key", type="password", help="Get your API key from https://openrouter.ai/keys")
        
        if api_key:
            try:
                # Test the API key with a simple call
                client = openai.OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=api_key,
                    default_headers={
                        "HTTP-Referer": "https://github.com/yourusername/support-router",
                        "X-Title": "Support Ticket Router"
                    }
                )
                
                # Test API connection
                test_response = client.chat.completions.create(
                    model="openai/gpt-4o-mini",
                    messages=[{"role": "user", "content": "Test connection"}],
                    max_tokens=10
                )
                
                st.session_state.openrouter_client = client
                st.success("✅ Agentic System Ready")
                st.success(f"✅ API Test: {test_response.choices[0].message.content[:20]}...")
                
            except Exception as e:
                st.error(f"❌ API Key Error: {str(e)}")
                st.error("Please check your OpenRouter API key and ensure you have credits")
                st.info("💡 Make sure to:")
                st.write("1. Get API key from https://openrouter.ai/keys")
                st.write("2. Add credits to your OpenRouter account")
                st.write("3. Copy the key exactly as shown")
        
        st.divider()

         # LOGS
        st.subheader("Server Logs")
        st.write(f"**{len(logs)} Server Logs Entries**")
        for i, log in enumerate(logs):
            with st.expander(f"Log {i+1}: {log['method']} {log['endpoint']}", expanded=False):
                st.write(f"**Timestamp:** {log['timestamp']}")
                st.write(f"**Client IP:** {log['client_ip']}")
                st.write(f"**Anomaly:** {log.get('anomaly', 'None')}")
        
        st.divider()
        
        # Statistics
        if st.session_state.processed_tickets:
            st.subheader("📊 Processing Stats")
            total_tickets = len(st.session_state.processed_tickets)
            st.metric("Tickets Processed", total_tickets)
            
            # Calculate success rate
            successful = sum(1 for t in st.session_state.processed_tickets 
                           if t.get('processing_complete', False))
            st.metric("Success Rate", f"{(successful/total_tickets)*100:.1f}%")


     # Main Interface
    st.header("Server Logs")
    st.subheader("Security Logs")

    if logs:
        df = pd.DataFrame(logs)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No logs available.")

    if st.button("Run Agent"):
        input_data = {
            "message": "Analyze this log"
        }

        # passing the openrouter client is needed since the
        # user is entering it here in the UI
        result = run_agent(input_data, st.session_state.openrouter_client)

        st.subheader("Agent Output")

        # Overall risk score
        risk_score = result.get("risk_score", 0)
        alert_type = result.get("alert_type")
        alert_confidence = result.get("alert_confidence", 0)

        if risk_score >= 0.7:
            risk_color = "🔴"
        elif risk_score >= 0.4:
            risk_color = "🟡"
        else:
            risk_color = "🟢"

        st.metric(
            label=f"{risk_color} Overall Risk Score",
            value=f"{risk_score:.0%}",
        )

        if alert_type:
            st.warning(f"Alert: **{alert_type}** (confidence: {alert_confidence:.0%})")

        risk_factors = result.get("risk_factors", [])
        if risk_factors:
            st.error("Risk Factors: " + ", ".join(risk_factors))

        # Build a single DataFrame with all feature scores
        feature_data = {}
        for key, label in [
            ("sequence_features", "Sequence"),
            ("payload_features", "Payload"),
            ("behavior_features", "Behavior"),
        ]:
            features = result.get(key, {})
            for name, score in features.items():
                display_name = name.replace("_", " ").title()
                feature_data[display_name] = {"Score": score, "Category": label}

        if feature_data:
            chart_df = pd.DataFrame.from_dict(feature_data, orient="index")
            st.bar_chart(chart_df["Score"])

    st.header('Security Vulnerabilities')

main()
