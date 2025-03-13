import json
from selenium import webdriver
from selenium.webdriver.common.by import By

def test_firefox():
    options = webdriver.FirefoxOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--headless")

    driver = webdriver.Firefox(options)
    print(driver.capabilities['browserVersion'])

    driver.get("view-source:https://localhost:8443/anything")
    driver.implicitly_wait(0.5)
    print(driver.page_source)

    content = driver.find_element(by=By.TAG_NAME, value='pre').text
    parsed_json = json.loads(content)

    assert parsed_json["headers"]["X-Http2-Fingerprint"] == "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:22|m,p,a,s"
    assert parsed_json["headers"]["X-Ja3-Fingerprint"] == "6f7889b9fb1a62a9577e685c1fcfa919"
    assert parsed_json["headers"]["X-Ja4-Fingerprint"] == "t13d1717h2_5b57614c22b0_3cbfd9057e0d"

    driver.quit()
