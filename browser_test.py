from playwright.sync_api import sync_playwright

def test_open_amazon_unsubscribe_page():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        url = "https://www.amazon.com/gp/r.html?C=3MK44JYNGBGBH&K=3UUPYKME0WJAX&M=urn:rtn:msg:202409121621586ef80839971b4dc2ae581dd770b0p0na&R=AYQ9C23H9UF9&T=X&U=https%3A%2F%2Fwww.amazon.com%2Fgp%2Fgss%2Fu%2F149F6WI4jIsDwljXTrAWiCMoa3-pkSa59qUyr41z5dhssO.kjPwm5d81QoKfwtItI%3Fref_%3DLF0502LNK&H=M668OPJJPHELDC8KEJCDNTHXI7UA"
        page.goto(url)
        print(f"Page title: {page.title()}")
        browser.close()

if __name__ == "__main__":
    test_open_amazon_unsubscribe_page()
