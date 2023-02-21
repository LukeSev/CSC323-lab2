import requests
import re

base_url = "http://localhost:8080"
register_url = base_url + "/register"
home_url = base_url + "/home"
logout_url = base_url + "/logout"

def getcookies(params):
    # Gets auth_token cookie for localhost signing in with given parameters

    with requests.Session() as sesh:
        reg = sesh.post(register_url, params)
        login = sesh.post(base_url, params)
        cookies = sesh.cookies.get_dict()
        return cookies

def get_auth_token(params):
    return getcookies(params)['auth_token']

def print_html_text(text):
    # Given raw html text, removes everything within <>'s and leading whitespace
    lines = re.sub('<.+?>', '', text).split("\n")
    for line in lines:
        # Don't print empty lines
        if(len(line.lstrip()) > 0):
            print(line.lstrip())

def admin_login(admin_cookie):
    # Given a cookie whose role is admin, prints text from home page after login
    with requests.Session() as admin_sesh:
        admin_sesh.cookies.set('auth_token', admin_cookie, domain="localhost:8080")

        cookies = {'auth_token':admin_cookie}
        adv_params = {'user':'admin', 'password':'password'}
        admin_sesh.post(register_url, adv_params)
        admin_sesh.post(base_url, adv_params)
        r = admin_sesh.get(home_url, cookies=cookies)
        print_html_text(r.text)
        

def main():
    adv_params = {'user':'test', 'password':'test'}
    test_params = {'user':'user', 'password':'user'}
    print(get_auth_token(adv_params))
    print(get_auth_token(test_params))

if __name__ == '__main__':
    main()