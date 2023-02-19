import requests

base_url = "http://localhost:8080"
register_url = base_url + "/register"
home_url = base_url + "/home"
logout_url = base_url + "/logout"

def getcookies(params):
    # Gets auth_token cookie for localhost signing in with given parameters

    with requests.Session() as sesh:
        reg = sesh.post(register_url, params)
        login = sesh.post(base_url, params)
        #home = sesh.post(home_url, params)
        cookies = sesh.cookies.get_dict()
        return cookies

def get_auth_token(params):
    return getcookies(params)['auth_token']

def admin_login(admin_cookie):
    with requests.Session() as admin_sesh:
        cookies = {'auth_token':admin_cookie}
        cookie_url = base_url + "/cookies/set/auth_token/" + admin_cookie
        print("In Cookie:  {}".format(cookies['auth_token']))
        adv_params = {'user':'mmhmmm', 'password':'password'}
        # admin_sesh.post(register_url, adv_params, cookies=cookies)
        # r = admin_sesh.post(base_url, adv_params, cookies=cookies)
        admin_sesh.get(cookie_url)
        admin_sesh.post(register_url, adv_params)
        r = admin_sesh.post(base_url, adv_params)
        #print(r.text)

        print("Out Cookie: {}".format(admin_sesh.cookies.get_dict()['auth_token']))

def main():
    adv_params = {'user':'test', 'password':'test'}
    test_params = {'user':'user', 'password':'user'}
    print(get_auth_token(adv_params))
    print(get_auth_token(test_params))
    #print("\nUSER: {} || PASSWORD: {}\n{}\n".format(adv_params['user'], adv_params['password'], get_auth_token(adv_params)))

if __name__ == '__main__':
    main()