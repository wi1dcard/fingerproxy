import json
from selenium import webdriver
from selenium.webdriver.common.by import By

def test_chrome():
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--headless")

    driver = webdriver.Chrome(options)
    print(driver.capabilities['browserVersion'])

    driver.get("https://localhost:8443/anything")
    content = driver.find_element(by=By.TAG_NAME, value='pre').text
    parsed_json = json.loads(content)
    print(parsed_json)

    assert parsed_json["headers"]["X-Http2-Fingerprint"] == "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p"
    assert parsed_json["headers"]["X-Ja4-Fingerprint"] == "t13d1516h2_8daaf6152771_02713d6af862"

    driver.quit()
