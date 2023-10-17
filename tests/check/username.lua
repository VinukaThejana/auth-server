local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("json")

local function help(params)
	for _, param in ipairs(params) do
		if param == "-h" or param == "--help" or param == "h" or param == "help" then
			print("USAGE : \n")

			print("\t- lua username.lua $username")
			print("\t\tThe username that needs to be checked from the database")
			print("")

			os.exit(0)
		end
	end
end

local param = arg[1]
if param == nil then
	param = "h"
end

help({ param })

local headers = {
	["Content-Type"] = "application/json",
}
local body = json:encode({
	username = param,
})

local r = {}
local _, code, _ = http.request({
	url = "http://localhost:8080/check/username",
	method = "POST",
	headers = headers,
	source = ltn12.source.string(body),
	sink = ltn12.sink.table(r),
})

local data = json:decode(r[1])
print("")
print("Is Available : ", data["is_available"])
print("Status       : ", data["status"])
print("Code         : ", code)
print("")
