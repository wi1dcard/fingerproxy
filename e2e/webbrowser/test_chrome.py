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
    driver.implicitly_wait(0.5)
    print(driver.page_source)

    content = driver.find_element(by=By.TAG_NAME, value='pre').text
    parsed_json = json.loads(content)

    # chrome version: 136.0.7103.92
    assert parsed_json["headers"]["X-Http2-Fingerprint"] == "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p"
    assert parsed_json["headers"]["X-Ja4-Fingerprint"] == "t13d1516h2_8daaf6152771_d8a2da3f94cd"

    driver.quit()
