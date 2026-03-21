#1. Kiem tra tech
import requests
import json
import os

def loc_dl_tu_api(domain:str):
    # API link (Chỉ Vi en)
    api_url = f"https://whois.inet.vn/api/whois/domainspecify/{domain}"
    try:
        response = requests.get(api_url)
        data = response.json()
        return data
    except Exception as e:
        print(f"Có lỗi xảy ra: {e}")
        return None


def kiem_tra_ten_mien(domain:str):

    # Chỗ lưu dữ liệu

    folder_name = "Ket_Qua_Web_Scrape"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    file_path = os.path.join(folder_name, f"{domain}.json")
    

    # API link (Chỉ Vi en)
    url = f"https://whois.inet.vn/api/whois/domainspecify/{domain}"
    
    try:
        # Gửi yêu cầu lấy dữ liệu
        response = requests.get(url)
        
        # Chuyển về json
        data = response.json()
        print(type(data))
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        i += 1
    except Exception as e:
        print(f"Có lỗi xảy ra: {e}")

    # Dưới này về sau chèn web scrape (Text, image,...)

 
# kiem_tra_ten_mien("svb.vn")

a = loc_dl_tu_api("svb.vn")
ten_mien = a.get("domainName")
ten_server = a.get("nameServer")
print(f"Ten Server thứ nhất: {ten_server[0]}") 
print(f"Tên miền: {ten_mien}")
print(f"Tên server: {ten_server}")