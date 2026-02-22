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
class PhishingDetector:
    def __init__(self, eml_path):
        with open(eml_path, 'rb') as f:
            self.msg = email.message_from_binary_file(f, policy=policy.default)
        self.scores = []
        self.findings = []
        
def analyze(self):
        print(f"Analyzing: {self.msg['Subject']}.....")
        
        #Analyse header
        sender = self.msg.get('From', '')
        domain = re.search(r"@([\w.-]+)", sender).group(1) if "@" in sender else None
        self.check_domain_age(domain)

        #Analyse URL
        body = self.msg.get_body(preferencelist=('html', 'plain')).get_content()
        self.check_urls(body)

        #Analyse content
        self.check_sentiment(body)

        #Analyse attachments 
        self.check_attachments()

        self.report()
        
def check_domain_age(self, domain):
        if not domain: return
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            
            age_days = (datetime.datetime.now() - creation_date).days
            if age_days < 90:
                self.findings.append(f"Domain: Registered only {age_days} days ago. May be suspicious")
        except:
            self.findings.append("whois lookup failed")

    def check_urls(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        links = soup.find_all('a', href=True)
        
        #check links
        for link in links:
            href = link['href']
            text = link.get_text()
            
            #Levenshtein mismatches
            if "http" in text:
                dist = Levenshtein.distance(text, href)
                if dist > 5:
                    self.findings.append(f"Link Mismatch Found: '{text}': '{href}'")

            # CCHeck for obfuscations
            if "@" in href.split("//")[-1]:
                self.findings.append(f"[!] URL Obfuscation: '@' symbol trick detected in {href}")

#sentiment checks
def check_sentiment(self, text):
        urgent_keywords = ["urgent", "immediately", "verify now", "account suspended"]
        found = [w for w in urgent_keywords if w in text.lower()]
        if found:
            self.findings.append(f"Urgent Language: {found}")

        def check_attachments(self):
             dangerous_exts = ['.exe', '.scr', '.bat', '.js', '.docm']
        for part in self.msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                ext = "." + filename.split('.')[-1]
                if ext in dangerous_exts:
                     self.findings.append(f"Dangerous Attachment: {filename}")

def report(self):
    for finding in self.findings:
        print(finding)
        if not self.findings:
            print("No immediate threats detected.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python phishing_detector.py <email.eml>")
    else:
        detector = PhishingDetector(sys.argv[1])
        detector.analyze()
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