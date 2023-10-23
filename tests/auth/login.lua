local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("json")

local function help(params)
	for _, param in ipairs(params) do
		if param == "-h" or param == "--help" or param == "h" or param == "help" then
			print("USAGE : \n")

			print("\t- lua login.lua $usernameOrEmail $password")
			print("\t\tThe username or email and the password that needs to login")
			print("")

			os.exit(0)
		end
	end
end

local usernameOrEmail = arg[1]
local password = arg[2]
if usernameOrEmail == nil or password == nil then
	usernameOrEmail = "h"
	password = "h"
end

help({ usernameOrEmail })

local headers = {
	["Content-Type"] = "application/json",
}

local body

if string.find(usernameOrEmail, "@") ~= nil then
	body = json:encode({
		email = usernameOrEmail,
		password = password,
	})
else
	body = json:encode({
		username = usernameOrEmail,
		password = password,
	})
end

local r = {}

local _, code, _ = http.request({
	url = "http://localhost:8080/auth/login",
	method = "POST",
	headers = headers,
	source = ltn12.source.string(body),
	sink = ltn12.sink.table(r),
})

local data = json:decode(r[1])

if code == 200 then
	print("")
	print("STATUS")
	print("")
	print("Status       : ", data["status"])
	print("Code         : ", code)

	print("")
	print("USER DETAILS")
	print("")
	local user = data["user"]
	print("ID           : ", user["id"])
	print("Name         : ", user["name"])
	print("Username     : ", user["username"])
	print("Email        : ", user["email"])
	print("PhotoURL     : ", user["photo_url"])
	print("")
	return
end

print("")
print("STATUS")
print("")
print("Status       : ", data["status"])
print("Code         : ", code)
print("")
