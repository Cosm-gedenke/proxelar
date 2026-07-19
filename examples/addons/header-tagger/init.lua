-- Example portable Proxelar addon.
function on_request(request)
    request.headers["x-proxelar-addon"] = "header-tagger"
    return request
end
