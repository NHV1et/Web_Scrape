#1. Kiem tra tech
import requests
import json
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
# Nếu dùng request thì khi mò web phải viết header user, còn request_html thì không cần,  
# nhưng request_html lại không lấy được dữ liệu từ API, nên mình sẽ dùng request để lấy dữ liệu từ API,  
# còn selenium để mò web nếu cần thiết (chưa biết mò cái gì)
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


def scrape_web_dong(url:str):
    url = url.strip()
    driver = webdriver.Firefox()
    driver.get(url)
    # Vet thong tin
    try:
        list_bao = []
        list_link = []
        list_lanh_dao = []
        #Cách tự cook
        #i = 1
        #ds_bao = driver.find_element(By.CLASS_NAME, "main-articles")
        # for bao in ds_bao.find_elements(By.CLASS_NAME, "main-article-item"):
        #     # Truy cập được vào từng cái div con được, xem document để chỉ lấy link hrefprint(bao.text.strip()) 
        #     print(f"Tiêu đề: {bao.text.strip()}")
        #     href_element = bao.find_element(By.XPATH, f"//*[@id='1']/div/div/div[1]/div[2]/div/div[{i}]/a")
        #     # Tức là phải lưu element muốn xuất thành một biến rồi mới get được
        #     print(f"Link: {href_element.get_attribute('href')}")
        #     i += 1

        #Cách tối ưu hơn
        for bao in driver.find_elements(By.CLASS_NAME, "main-article-item"):
            #Không cần phải truy cập vào div cha trước rồi mới vào div con 
            #Do cái find_elements trả về một list rồi 
            #print(f"Tiêu đề: {bao.text.strip()}")
            list_bao.append(bao.text.strip())
            href_element = bao.find_element(By.TAG_NAME, "a")
            list_link.append(href_element.get_attribute('href'))
            #print(f"Link: {href_element.get_attribute('href')}")
        for lanh_dao in driver.find_elements(By.CLASS_NAME,"home__ptt-item"):
            pass
            ten = lanh_dao.find_element(By.CLASS_NAME,"role")
            chuc_vu = lanh_dao.find_element(By.CLASS_NAME,"name")
            href_element = lanh_dao.find_element(By.TAG_NAME,"a")
            link_profile = href_element.get_attribute('href')
            list_lanh_dao.append(f"Name: {ten.text.strip()}, Chuc vu: {chuc_vu.text.strip()} , link: {link_profile}")
            
        data_dict = {"Tiêu đề": list_bao, "Link": list_link, "Lãnh đạo":list_lanh_dao}
        print(data_dict)
        with open("Ket_Qua_Web_Scrape/Thong_Tin_Bao_Chinh_Phu.json", "w", encoding="utf-8") as f:
            json.dump(data_dict, f, indent=4, ensure_ascii=False)
        driver.quit()
        list_lanh_dao.clear()
        list_bao.clear()
        list_link.clear()
    except NoSuchElementException as e:
        print(f"Có lỗi xảy ra khi tìm kiếm phần tử: {e}")
        

scrape_web_dong("https://chinhphu.vn/")
# kiem_tra_ten_mien("svb.vn")

# a = loc_dl_tu_api("svb.vn")
# ten_mien = a.get("domainName")
# ten_server = a.get("nameServer")
# print(f"Ten Server thứ nhất: {ten_server[0]}") 
# print(f"Tên miền: {ten_mien}")
# print(f"Tên server: {ten_server}")

