import streamlit as st
import requests
import whois
import dns.resolver
import hashlib
import os
import json
import time
import math

# Set your VirusTotal API Key
VT_API_KEY = "your_api_key_here"

def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return {
            "Domain": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiry Date": domain_info.expiration_date,
            "Name Servers": domain_info.name_servers,
        }
    except Exception as e:
        return {"Error": str(e)}


def dns_lookup(domain):
    records = {}
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except:
            records[record_type] = "Not found"
    return records

def domain_reputation(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"Error": "VirusTotal API Error"}

def main():
    st.title("Cybersecurity Analysis Tool")
    
    mode = st.radio("Choose mode", ["Domain Analysis", "File Analysis"])
    
    if mode == "Domain Analysis":
        domain = st.text_input("Enter domain name")
        if st.button("Analyze Domain"):
            with st.spinner("Analyzing domain..."):
                whois_result = whois_lookup(domain)
                dns_result = dns_lookup(domain)
                reputation_result = domain_reputation(domain, VT_API_KEY)
            
            st.subheader("WHOIS Information")
            st.json(whois_result)
            st.subheader("DNS Records")
            st.json(dns_result)
            st.subheader("VirusTotal Reputation")
            st.json(reputation_result)
    
    elif mode == "File Analysis":
        uploaded_file = st.file_uploader("Upload a file for analysis")
        if uploaded_file and st.button("Analyze File"):
            with open("temp_file", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            sha256_hash = hashlib.sha256(open("temp_file", "rb").read()).hexdigest()
            md5_hash = hashlib.md5(open("temp_file", "rb").read()).hexdigest()
            
            st.subheader("File Hashes")
            st.write(f"SHA256: {sha256_hash}")
            st.write(f"MD5: {md5_hash}")
            os.remove("temp_file")

if __name__ == "__main__":
    main()
