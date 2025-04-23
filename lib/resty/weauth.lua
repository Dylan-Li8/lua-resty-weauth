-- Copyright (C) K8sCat<k8scat@gmail.com>
-- https://open.work.weixin.qq.com/api/doc/90000/90135/90664

local json = require("cjson")
local jwt = require("resty.jwt")
local http = require("resty.http")
local ngx = require("ngx")

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end

local jwt_header_alg = "HS256"

local _M = new_tab(0, 32) -- Increased estimated size slightly

_M._VERSION = "0.0.4" -- Bump version

_M.corp_id = ""
_M.app_agent_id = ""
_M.app_secret = ""
_M.callback_uri = "/weauth_callback"
_M.app_domain = ""

_M.jwt_secret = ""
_M.jwt_expire = 86400 -- 24小时

_M.only_wxwork_browser = false
_M.qrConnect = false

_M.logout_uri = "/weauth_logout"
_M.logout_redirect = "/"

_M.cookie_key = "weauth_token"

_M.ip_blacklist = {}
_M.uri_whitelist = {}
_M.department_whitelist = {}
_M.force_auth_uris = {} -- <<< 新增：强制验证的URI列表

local function http_get(url, query)
    local request = http.new()
    request:set_timeout(10000)
    return request:request_uri(url, {
        method = "GET",
        query = query,
        ssl_verify = false
    })
end

local function has_value(tab, val)
    -- 确保 tab 是一个有效的 table 且 val 不是 nil
    if type(tab) ~= "table" or val == nil then
        return false
    end
    for i=1, #tab do
        if tab[i] == val then
            return true
        end
    end
    return false
end

local function is_wxwork_browser()
    local user_agent = ngx.var.http_user_agent or ""
    return user_agent:lower():find("wxwork") ~= nil
end

function _M:get_access_token()
    local url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    local query = {
        corpid = self.corp_id,
        corpsecret = self.app_secret
    }
    local res, err = http_get(url, query)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local data = json.decode(res.body)
    -- 检查 data 是否为 nil 以及 errcode 是否存在
    if not data or data["errcode"] == nil or data["errcode"] ~= 0 then
        return nil, res.body or "invalid json response"
    end
    return data["access_token"]
end

function _M:sso()
    local uri
    local url_args
    local state

    local callback_url = ngx.var.scheme .. "://" .. self.app_domain .. self.callback_uri
    local redirect_url = ngx.var.scheme .. "://" .. self.app_domain .. ngx.var.request_uri
    local args = {
        appid = self.corp_id,
        agentid = self.app_agent_id,
        redirect_uri = callback_url
    }

    if self.qrConnect then
        uri = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect?"
        args.state = redirect_url -- state for qrConnect
        url_args = ngx.encode_args(args)
    else
        uri = "https://open.weixin.qq.com/connect/oauth2/authorize?"
        args.response_type = "code"
        args.scope = "snsapi_base"
        state = ngx.escape_uri(redirect_url) -- state for oauth2
        url_args = ngx.encode_args(args) .. "&state=" .. state .. "#wechat_redirect"
    end

    ngx.log(ngx.ERR, "redirect uri: ", uri, ", args: ", url_args)
    return ngx.redirect(uri .. url_args)
end

function _M:clear_token()
    -- 清除主 token 和可能存在的 userid cookie
    ngx.header["Set-Cookie"] = {
        self.cookie_key .. "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/;",
        "userid=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/;"
    }
end

function _M:logout()
    self:clear_token()
    return ngx.redirect(self.logout_redirect)
end

function _M:get_user_id(access_token, code)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
    local query = {
        access_token = access_token,
        code = code,
    }
    local res, err = http_get(url, query)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local user = json.decode(res.body)
    -- 检查 user 是否为 nil 以及 errcode 是否存在
    if not user or user["errcode"] == nil or user["errcode"] ~= 0 then
        return nil, res.body or "invalid json response"
    end
    return user["UserId"]
end

function _M:get_user(access_token, user_id)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
    local query = {
        access_token = access_token,
        userid = user_id
    }
    ngx.log(ngx.ERR, "get user query: ", json.encode(query))
    local res, err = http_get(url, query)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local user = json.decode(res.body)
     -- 检查 user 是否为 nil 以及 errcode 是否存在
    if not user or user["errcode"] == nil or user["errcode"] ~= 0 then
        return nil, res.body or "invalid json response"
    end
    return user
end

function _M:verify_token()
    -- 从 ngx.var.cookie_* 中获取 cookie 值
    local token = ngx.var['cookie_' .. self.cookie_key]
    ngx.log(ngx.ERR, "ngx.var.cookie_", self.cookie_key, " :", token)
    if not token or token == "" then
        return nil, "token not found in cookie"
    end

    -- 确保 jwt_secret 不为空
    if not self.jwt_secret or self.jwt_secret == "" then
        ngx.log(ngx.ERR, "jwt_secret is not configured")
        return nil, "server configuration error: jwt secret missing"
    end

    -- 使用 pcall 捕获 jwt:verify 可能抛出的错误
    local ok, result = pcall(jwt.verify, jwt, self.jwt_secret, token)
    if not ok then
        ngx.log(ngx.ERR, "jwt:verify error: ", result) -- result contains the error message
        return nil, "token verification failed: " .. tostring(result)
    end

    ngx.log(ngx.ERR, "jwt_obj: ", json.encode(result))
    if result and result["valid"] then
        local payload = result["payload"]
        -- 检查 payload 是否存在且包含必要字段
        if payload and payload["userid"] and payload["department"] then
            -- 尝试解码 department，如果失败则认为 token 无效
            local decode_ok, decoded_department = pcall(json.decode, payload["department"])
            if decode_ok and type(decoded_department) == "table" then
                 -- 将解码后的 department 存回 payload，方便后续使用
                 payload["department"] = decoded_department
                 return payload
            else
                 ngx.log(ngx.ERR, "invalid token: department is not a valid json array string. Original: ", payload["department"])
                 return nil, "invalid token: malformed department data"
            end
        end
        ngx.log(ngx.ERR, "invalid token: missing required fields (userid or department). Payload: ", json.encode(payload))
        return nil, "invalid token: missing required fields"
    end
    -- 提供更具体的无效原因
    local reason = result and result["reason"] or "unknown reason"
    ngx.log(ngx.ERR, "invalid token: ", reason, " Raw result: ", json.encode(result))
    return nil, "invalid token: " .. reason
end

function _M:sign_token(user)
    local user_id = user["userid"]
    if not user_id or user_id == "" then
        return nil, "invalid userid"
    end
    local department_ids = user["department"]
    -- 确保 department_ids 是一个 table
    if not department_ids or type(department_ids) ~= "table" then
        return nil, "invalid department (must be a table)"
    end
    -- 确保 jwt_secret 不为空
    if not self.jwt_secret or self.jwt_secret == "" then
        ngx.log(ngx.ERR, "jwt_secret is not configured for signing")
        return nil, "server configuration error: jwt secret missing for signing"
    end
    -- 将部门列表编码为 JSON 字符串存储
    local department_json = json.encode(department_ids)

    local jwt_payload = {
        header = {
            typ = "JWT",
            alg = jwt_header_alg,
        },
        payload = {
            userid = user_id,
            department = department_json, -- Store as JSON string
            exp = ngx.time() + self.jwt_expire -- Expiration time in payload
        }
    }

    -- 使用 pcall 捕获 jwt:sign 可能的错误
    local ok, token = pcall(jwt.sign, jwt, self.jwt_secret, jwt_payload)
    if not ok then
        ngx.log(ngx.ERR, "jwt:sign error: ", token) -- token contains error message here
        return nil, "token signing failed: " .. tostring(token)
    end

    return token
end

function _M:check_user_access(user_or_payload)
    -- 如果部门白名单为空，则所有人都允许访问
    if type(self.department_whitelist) ~= "table" or #self.department_whitelist == 0 then
        ngx.log(ngx.DEBUG, "department_whitelist is empty or not a table, access granted.")
        return true
    end

    local department_ids = user_or_payload["department"]

    -- 从 verify_token 来的 payload，department 已经是 table
    -- 从 get_user 来的 user，department 也是 table
    -- 这里不再需要 json.decode
    if not department_ids or type(department_ids) ~= "table" then
        ngx.log(ngx.ERR, "User/Payload department data is missing or not a table. Data: ", json.encode(user_or_payload))
        return false
    end

    ngx.log(ngx.DEBUG, "Checking user departments: ", json.encode(department_ids), " against whitelist: ", json.encode(self.department_whitelist))

    for i=1, #department_ids do
        if has_value(self.department_whitelist, department_ids[i]) then
            ngx.log(ngx.DEBUG, "User department ", department_ids[i], " found in whitelist. Access granted.")
            return true
        end
    end

    ngx.log(ngx.WARN, "User departments ", json.encode(department_ids), " not found in whitelist. Access denied.")
    return false
end

function _M:sso_callback()
    local request_args = ngx.req.get_uri_args()
    if not request_args then
        ngx.log(ngx.ERR, "sso_callback: Missing request arguments")
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    local code = request_args["code"]
    if not code then
        ngx.log(ngx.ERR, "sso_callback: Missing 'code' argument")
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    ngx.log(ngx.INFO, "sso_callback: Received code: ", code)

    local access_token, err = self:get_access_token()
    if not access_token then
        ngx.log(ngx.ERR, "sso_callback: get access_token failed: ", err)
        -- 可以考虑返回更友好的错误页面或重定向
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.DEBUG, "sso_callback: Got access_token")

    local user_id, err = self:get_user_id(access_token, code)
    if not user_id then
        ngx.log(ngx.ERR, "sso_callback: get user id failed: ", err)
         -- 如果是无效code导致的，可以尝试重新发起SSO
        if err and type(err) == "string" and err:find("invalid code") then
             ngx.log(ngx.WARN, "sso_callback: Invalid code detected, redirecting to SSO again.")
             return self:sso()
        end
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.INFO, "sso_callback: Got user id: ", user_id)

    local user, err = self:get_user(access_token, user_id)
    if not user then
        ngx.log(ngx.ERR, "sso_callback: get user details failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.INFO, "sso_callback: Got login user details: ", json.encode(user))

    -- 检查用户部门权限
    if not self:check_user_access(user) then
        ngx.log(ngx.WARN, "sso_callback: User ", user_id, " access not permitted based on department whitelist.")
        -- 用户在企业微信中，但部门不被允许，可以提示无权限或重定向到无权限页面，或者重新SSO（意义不大，除非用户切换了账号）
        -- 这里选择清除可能存在的旧token并重新SSO，寄希望于用户能切换到有权限的账号
        self:clear_token()
        -- 返回一个友好的错误提示可能更好，而不是直接重定向SSO
        -- ngx.status = ngx.HTTP_FORBIDDEN
        -- ngx.say("Access Denied: Your department does not have permission.")
        -- ngx.exit(ngx.HTTP_FORBIDDEN)
        -- 或者，如果希望用户尝试切换账号，可以重定向到SSO
        return self:sso()
    end
    ngx.log(ngx.DEBUG, "sso_callback: User ", user_id, " passed department check.")

    local token, err = self:sign_token(user)
    if not token then
        ngx.log(ngx.ERR, "sso_callback: sign token failed: ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR) -- 签名失败是服务器内部问题
    end
    ngx.log(ngx.INFO, "sso_callback: Token signed successfully for user: ", user_id)

    -- 设置包含token的cookie 和 包含userid的cookie（可选，但可能有用）
    local cookie_flags = "; Path=/; HttpOnly"
    -- 如果是 https，可以加上 Secure 标志: if ngx.var.scheme == "https" then cookie_flags = cookie_flags .. "; Secure" end
    if ngx.var.scheme == "https" then cookie_flags = cookie_flags .. "; Secure" end

    ngx.header["Set-Cookie"] = {
        self.cookie_key .. "=" .. token .. cookie_flags,
        "userid=" .. user['userid'] .. cookie_flags -- 设置 userid cookie
    }

    ngx.log(ngx.DEBUG, "sso_callback: Set cookies: ", self.cookie_key, " and userid")

    local redirect_url = request_args["state"]
    -- 对 redirect_url 做基本的安全检查，防止开放重定向漏洞
    -- 简单的检查：确保它以 / 开头或者是配置中的 app_domain
    local safe_redirect = "/" -- 默认重定向到根目录
    if redirect_url and type(redirect_url) == "string" then
        if string.sub(redirect_url, 1, 1) == "/" then -- 允许站内相对路径
            safe_redirect = redirect_url
        elseif self.app_domain and redirect_url:find(ngx.var.scheme .. "://" .. self.app_domain, 1, true) == 1 then -- 允许本站绝对路径
             safe_redirect = redirect_url
        else
            ngx.log(ngx.WARN, "sso_callback: Unsafe redirect state detected: ", redirect_url, ". Redirecting to root.")
        end
    end

    ngx.log(ngx.INFO, "sso_callback: Redirecting to: ", safe_redirect)
    return ngx.redirect(safe_redirect)
end

function _M:auth()
    local request_uri = ngx.var.uri
    ngx.log(ngx.DEBUG, "auth: Processing request for URI: ", request_uri)

    -- 判断是否企业微信浏览器 (如果开启了 only_wxwork_browser)
    if self.only_wxwork_browser and not is_wxwork_browser() then
        ngx.header.content_type = 'text/plain; charset=utf-8'
        ngx.log(ngx.WARN, "auth: Access denied. Request not from WxWork browser. URI: ", request_uri)
        return ngx.say("请在企业微信客户端或应用内打开") -- 修改了提示信息
    end

    -- <<< 修改点开始 >>>
    -- 检查 URI 是否在白名单中
    local is_whitelisted = has_value(self.uri_whitelist, request_uri)
    -- 检查 URI 是否在强制验证列表中
    local requires_force_auth = has_value(self.force_auth_uris, request_uri)

    -- 只有当URI在白名单中，并且 *不在* 强制验证列表中时，才跳过验证
    if is_whitelisted and not requires_force_auth then
        ngx.log(ngx.INFO, "auth: URI '", request_uri, "' is whitelisted and does not require forced auth. Access granted without auth check.")
        return -- 直接放行
    elseif requires_force_auth then
         ngx.log(ngx.INFO, "auth: URI '", request_uri, "' requires forced authentication, proceeding with auth checks.")
         -- 不需要做任何事，继续执行后续的认证逻辑
    else
         -- URI 不在白名单中，继续执行后续的认证逻辑
         ngx.log(ngx.DEBUG, "auth: URI '", request_uri, "' is not whitelisted or requires forced auth, proceeding with auth checks.")
    end
    -- <<< 修改点结束 >>>

    -- IP 黑名单检查
    local request_ip = ngx.var.remote_addr
    if has_value(self.ip_blacklist, request_ip) then
        ngx.log(ngx.WARN, "auth: Access denied. IP '", request_ip, "' is in blacklist. URI: ", request_uri)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    -- 登出处理
    if request_uri == self.logout_uri then
        ngx.log(ngx.INFO, "auth: Handling logout request for URI: ", request_uri)
        return self:logout()
    end

    -- 尝试验证 Token
    ngx.log(ngx.DEBUG, "auth: Attempting to verify token for URI: ", request_uri)
    local payload, err = self:verify_token()

    if payload then
        ngx.log(ngx.INFO, "auth: Token verified successfully for user: ", payload.userid, ". URI: ", request_uri)
        -- Token 有效，检查部门权限
        if self:check_user_access(payload) then
            ngx.log(ngx.INFO, "auth: User ", payload.userid, " access permitted based on department. Access granted. URI: ", request_uri)
            -- 权限通过，设置用户信息到 header (可选)
            ngx.req.set_header("X-WEAUTH-USERID", payload.userid)
            ngx.req.set_header("X-WEAUTH-DEPARTMENT", json.encode(payload.department)) -- 传递部门信息给后端
            return -- 放行请求
        else
            -- 有 Token 但部门权限不足
            ngx.log(ngx.WARN, "auth: User ", payload.userid, " access denied. Department check failed. URI: ", request_uri)
            self:clear_token() -- 清除无效 Token
            -- 可以选择返回 403 页面或重定向到 SSO 让用户尝试切换账号
            -- ngx.exit(ngx.HTTP_FORBIDDEN) -- 或者
            return self:sso() -- 重定向到 SSO
        end
    else
        -- Token 无效或不存在
        ngx.log(ngx.INFO, "auth: Token verification failed or token not found: ", err, ". URI: ", request_uri)

        -- 如果当前请求不是回调 URI，则重定向到 SSO
        if request_uri ~= self.callback_uri then
            ngx.log(ngx.INFO, "auth: Redirecting to SSO. Current URI '", request_uri, "' is not the callback URI '", self.callback_uri, "'.")
            return self:sso()
        else
            -- 如果当前请求是回调 URI，则处理回调逻辑
            ngx.log(ngx.INFO, "auth: Handling SSO callback for URI: ", request_uri)
            return self:sso_callback()
        end
    end
end

return _M
