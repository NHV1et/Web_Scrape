import ssl
import socket
import subprocess
import requests
import re
import json
from datetime import datetime,timezone
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def perfect_url(url:str):
    if not url.startswith(("https://","http://")):
        url="https://"+url
    return url
def clean_label(title:str):
    print('----------------')
    print(f'   {title}')
    print('----------------')       
# ssl - domain - subdomain - dns - port - technologies - page_data
'''
  1.SSL: Chứng chỉ số bảo mật giữa trang web và máy chủ, hiển thị qua https
  2.Domain: Tên miền định danh duy nhất của trang web, định dạng ngắn thay cho địa chỉ IP khó nhớ
  3.Subdomain: Một nhánh phụ của tên miền chính, được phân chia nhỏ để phục vụ phần việc riêng của web
  4.DNS: Hệ thống phân giải tên miền, giúp chuyển đổi tên miền thành dải địa chỉ IP khi người dùng nhập tên miền trên Internet
  5.Port: Cổng phân biệt các kết nối mạng và định tuyến dữ liệu đến đúng dịch vụ hoặc ứng dụng
  6.Technologies: Công nghệ mà trang web đang dùng
  7.Page data (lite): Nội dung có trong trang web lấy từ html(scripts,styles) 
'''
def get_ssl_info(domain,output):
    clean_label('SSL')
    try:
        context = ssl.create_default_context()        
        # port 443 (HTTPS default)
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher=ssock.cipher()
                version=ssock.version()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                issued_to = subject.get('commonName', 'N/A')
                issued_by = issuer.get('commonName', 'N/A')
                issue_date = cert.get('notBefore', 'N/A')
                expiry_date = cert.get('notAfter', 'N/A')
                res={
                    'TLS_version':version,
                    'Cipher':cipher,
                    'Issued_to': issued_to,
                    'Issued_by': issued_by,
                    'Issue_date': issue_date,
                    'Expiry_date': expiry_date                    
                }
                output['ssl']=res

    except (socket.error, ssl.SSLError, ConnectionError) as e:
        print(f"Error retrieving SSL info for {domain}: {e}")
def get_domain_info(domain,output:dict):
    clean_label('Domain')
    result=subprocess.run(['whois',domain],capture_output=True,text=True)
    data=result.stdout
    info={}
    if not data.__contains__('no whois server'):
            patterns = {
                "Registrar":         r"Registrar:\s*(.+)",
                "Creation Date":     r"Creation Date:\s*(.+)",
                "Updated Date":      r"Updated Date:\s*(.+)",
                "Expiry Date":       r"Registry Expiry Date:\s*(.+)",
                "DNSSEC":            r"DNSSEC:\s*(.+)",
                "Registrant Org":    r"Registrant Organization:\s*(.+)",
                "Registrant Country":r"Registrant Country:\s*(.+)",
            }
            for field, pattern in patterns.items():
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    val = matches[0] if isinstance(matches[0], str) else next((m for m in matches[0] if m), "")
                    info[field] = val.strip()
                    #Tính tuổi đời tên miền            
            createdAt=info['Creation Date']
            formatedDate=datetime.fromisoformat(createdAt.replace('Z','+00:00'))
            now=datetime.now(timezone.utc)
            delta=(now-formatedDate)
            total_days=delta.days
            years = total_days // 365
            months = (total_days % 365) // 30
            days = (total_days % 365) % 30    
            info['Domain Age']=f'{years} years, {months} months, {days} days'        
            output['whois']=info
    else:
        print('[Lỗi] Whois không quét được hoặc không nằm trong database')
def get_subdomain(domain,output):
    clean_label('Subdomain')
    result = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", verify=False)
    founded=[]
    if result.status_code==200:
        res=result.json()
        subs=set()
        for i in res:
            names=i.get("name_value","").split("\n")
            for n in names:
                n=n.strip().lstrip("*.")
                if n.endswith(domain) and n!=domain:   
                    subs.add(n)
        founded=sorted(subs)            
    output['subdomain']=founded                                         
def get_dns_info(domain,output):
    clean_label('DNS')
    '''
      A: Địa chỉ IPv4
      AAAA: Địa chỉ IPv6
      MX: Máy chủ nhận thư điện tử
      NS: Máy chủ tên miền
      TXT: Lưu trữ thông tin văn bản trong bản ghi
      CNAME: Chuyển 1 domain hoặc subdomain đến 1 domain khác mà không cung cấp địa chỉ IP 
      SOA: Lưu trữ thông tin quản trị về tên miền 
    '''
    records_list=['A','AAAA',"MX",'NS','TXT','CNAME','SOA']
    info={}
    for type in records_list:
        result=subprocess.run(['dig','+short',type,domain],capture_output=True,text=True)
        records=[]
        if result.stdout.strip():
          for line in result.stdout.strip().splitlines():
            if line.strip():
                records.append(line)
                info[type]=records
    #Reverse dns
    # ip=socket.gethostbyname(domain)
    # rev=socket.gethostbyaddr(ip)[0]
    # info['Reverse_dns']=rev
    output['DNS']=info
    # for field ,val in info.items():
    #     print(f'* {field}')
    #     for i in val:
    #        if isinstance(val,list): 
    #           print(f'-{i}')
    #        else:
    #           print(f'-{val}')
    #           break 
def get_port_info(domain,output):
    clean_label('Port')
    '''
      1.80: HTTP - truyền dữ liệu không mã hóa
      2.443: HTTPS - truyền dữ liệu mã hóa bằng SSL/TLS
      3.25: SMTP - Gửi email
      4.20,21: FTP - Truyền tệp tin
      5.110: POP3 - Nhận email
      6.140: IMAP - Nhận email
    '''
    try:
        command=['nmap','-sV','--top-ports','100','--open','-T4','--script=banner',domain]      
        result = subprocess.run(command, capture_output=True, text=True)
        if result.stdout:
            ports=[]
            for line in result.stdout.splitlines():
                m = re.match(r'\s*(\d+)/(\w+)\s+open\s+(.+)', line)
                if m:
                    port, proto, service = m.groups()
                    ports.append({"Port": port, "Proto": proto, "Service": service.strip()})
            output['Port']=ports
            # k=1
            # for i in ports:
            #     print(f'-Port {k}:')
            #     for field,val in i.items():
            #         print(field,':',val)
            #     k+=1
    except subprocess.CalledProcessError as e:
        return f"[!] Lỗi: {e.stderr}"   
def get_tech_info(url,output):
    clean_label('Technologies')
    result=subprocess.run(['whatweb',url,'--log-json=-'],capture_output=True,text=True)
    tech={}
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            try:
                data = json.loads(line)                  
            except json.JSONDecodeError:
                continue          
    plugins=data.get('plugins',{})
    for name,val in plugins.items():
        info={}
        if 'version' in val:  
            info['version']=val['version']
        if 'string' in val:
            info['string']=val['string']

        tech[name]=info
    print(plugins)        
    categories = {
        "CMS":        ["WordPress", "Joomla", "Drupal", "Magento", "Shopify"],
        "Framework":  ["Laravel", "Django", "Ruby-on-Rails", "ASP_NET", "Express"],
        "Server":     ["Apache", "Nginx", "IIS", "LiteSpeed"],
        "Language":   ["PHP", "Python", "Ruby", "Java"],
        "JavaScript": ["jQuery", "React", "Vue.js", "Angular", "Bootstrap"],
        "Security":   ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy"],
    }

    categorized = {cat: {} for cat in categories}

    for tech_name, tech_info in tech.items():
        for cat, keywords in categories.items():
            if any(k.lower() in tech_name.lower() for k in keywords):
                categorized[cat][tech_name] = tech_info
                break
    output['Tech']=categorized   
def get_page_data(url,output):
    clean_label('Page data')
    res=requests.get(url,verify=False)
    soup=BeautifulSoup(res.text,'html.parser')
    title = soup.find("title")
    desc  = soup.find("meta", {"name": re.compile(r"^description$", re.I)})
    lang  = soup.find("html")
    
    links = soup.find_all("a", href=True)
    forms = soup.find_all("form")
    scripts = soup.find_all("script", src=True)
    styles  = soup.find_all("link", rel=re.compile("stylesheet", re.I))
    info={
        'Title':title.text.strip() if title else None,
        'Language':lang.get('lang') if lang else None,
        'Description':desc['content'] and desc.get('content') if desc else None,
        'Links':len(links),
        'Forms':len(forms),
        'Script':len(scripts),
        'Styles':len(styles)
    }
    output['Page_data']=info  
#--------------------------
#          MAIN
#--------------------------
domain = "chinhphu.vn"
url=perfect_url(domain)
report={}
get_ssl_info(domain,report)
get_domain_info(domain,report)
get_subdomain(domain,report)
get_tech_info(url,report)
get_dns_info(domain,report) 
get_port_info(domain,report)
get_page_data(url,report)
now= datetime.now().strftime("%Y%m%d_%H%M%S")
with open(f'report_{domain}_{now}.json','w') as f:
    json.dump(report,f,indent=2,ensure_ascii=False)
