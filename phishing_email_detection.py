import sys
import email
import re
import whois
import datetime
import Levenshtein
from email import policy
from bs4 import BeautifulSoup

#use cli interface 
#python phishing_email_detection.py <email.eml>

#extract_sender_domain(email_headers)

#check_spf_dkim_dmarc(headers)

#detect domain impersonation 

#check_mismatch_between_link_text_and_href(html)
#calculate and display Levenshtein distance

#check_url_reputation(url)
#IP address instead of domain
#Suspicious TLDs (.xyz, .top, etc.)
#URL shortening services
#Long or encoded URLs

#detect_url_obfuscation(url)
#check
#Hex encoding
#@ symbol tricks
#Excessive subdomains
#Unicode characters

#check_domain_age(domain)
#WHOIS lookup
#Flag domains registered recently (e.g., < 90 days)

#detect_urgent_language(text)
#"urgent"
#"immediately"
#"verify now"
#"account suspended"

#detect_threat_language(text)

#detect_suspicious_keywords(text)

#suspicious_words = {
#    "password": 2,
#    "verify": 3,
#    "bank": 2,
#    "login": 2,
#    "click here": 3
#}

#analyze_spelling_grammar(text) #use dedicated language libraries

#detect_dangerous_attachments(files)

#Flag:
#.exe
#.scr
#.bat
#.js
#.docm
#.zip

#scan_attachment_hash(file)
#Generate SHA256