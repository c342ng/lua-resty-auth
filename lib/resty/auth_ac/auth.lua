
local _M = {
    _VERSION = "0.0.1"
}

local m_t = {
    __index = _M
}

function _M.new(config_t)
    local default_t = {
        oauth_verify_server = "http://127.0.0.1:8080/api/verify",
        oauth_login_server = "http://127.0.0.1:8080/api/login/dingtalk/appid",
        server_login_url = "http://127.0.0.1:8081/oauth/login",
        cookie_expire = 3600,
        jwt_key = "jwt_sample_key",
    }
    for k,v in pairs(config_t) do
        default_t[k] = v
    end
    return setmetatable(default_t, m_t)
end

function _M.gen_redirect_uri_s(self,current_url,msg)
    local url =self.server_login_url.."?from="..ngx.escape_uri(current_url)
    local url = self.oauth_login_server.."?from="..ngx.escape_uri(url).."&msg="..ngx.escape_uri(msg)
    return url
end

-- return jwt_payload,redirect_uri,fail_err
function _M.verify_jwt(self, login_user, jwt_token, current_url)
    local jwt = require "resty.jwt"
    local jwt_obj = jwt:verify(self.jwt_key, jwt_token)
    if not jwt_obj.valid or not jwt_obj.verified then
        ngx.log(ngx.ERR,jwt_obj.reason)
        return nil, self:gen_redirect_uri_s( current_url,"验证失败"), "verify fail"
    end
    local expireAt, err = jwt_obj.payload.expireAt
    if err then
        ngx.log(ngx.ERR,"jwt_obj.payload.expireAt not found")
        return  nil, self:gen_redirect_uri_s(current_url,"凭证信息缺失expireAt"), "expireAt not found"
    end
    if expireAt == ngx.null or expireAt < os.time() then
        ngx.log(ngx.ERR,expireAt, " ", os.time())
        return  nil, self:gen_redirect_uri_s( current_url,"登陆信息已过期"), "sess timeout"
    end
    local currentUser, err = jwt_obj.payload.uid
    if err then
        ngx.log(ngx.ERR,"jwt_obj.payload.currentUser not found")
        return  nil, self:gen_redirect_uri_s( current_url,"凭证信息缺失user"), "user not found"
    end
    if currentUser == ngx.null or currentUser ~=login_user then
        ngx.log(ngx.ERR,"jwt_obj.payload.currentUser not match login user")
        return  nil, self:gen_redirect_uri_s(current_url,"非法凭证信息"), "user not match"
    end
    return jwt_obj.payload, "", nil
end
-- return user_info,fail_err
function _M.verify_code(self, code)
    local httpc = require("resty.http").new()
    local res, err = httpc:request_uri(self.oauth_verify_server.."?code="..code, {
        method = "GET"
    })
    httpc:close()
    if not res then
        ngx.log(ngx.ERR, "request failed: ", err)
        return nil, "request failed: ", err
    end
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "remote server status ",res.status)
        return nil,"remote server status "..res.status
    end
    local cjson = require "cjson"
    local info_t = cjson.decode(res.body)
    if info_t == ngx.null then
        ngx.log(ngx.ERR, "body not json ",res.body)
        return nil,"body not json"
    end
    return info_t,nil
end

function _M.gen_jwt(self,info_t)
    local jwt = require "resty.jwt"
    local jwt_token = jwt:sign(
        self.jwt_key,
        {
            header={typ="JWT", alg="HS256"},
            payload=info_t
        }
    )
    return jwt_token
end
return _M
