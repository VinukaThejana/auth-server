local Faker = require("faker")
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("json")

local faker = Faker:new()

local function help(params)
	for _, param in ipairs(params) do
		if param == "-h" or param == "--help" or param == "h" or param == "help" then
			print("USAGE : \n")

			print("\t- lua register.lua")
			print("\t\tProvide the register route with one real account")
			print("")

			print("\t- lua register.lua all")
			print("\t\tSpam the register route with a bunch of real and fake accounts")
			print("")
			print("\t\t-- lua register.lua all real")
			print("\t\t\tSpam the register route with all the real users")
			print("")
			os.exit(0)
		end
	end
end

local function register(name, username, email, password)
	local headers = {
		["Content-Type"] = "application/json",
	}
	local body = json:encode({
		name = name,
		username = username,
		email = email,
		password = password,
	})

	local r = {}
	local _, code, _ = http.request({
		url = "http://localhost:8080/auth/register",
		method = "POST",
		headers = headers,
		source = ltn12.source.string(body),
		sink = ltn12.sink.table(r),
	})

	if code == 500 then
		print(r[1])
		return
	end

	print(json:decode(r[1])["status"])
end

local users = {
	{
		["name"] = "Vinuka Kodituwakku",
		["username"] = "VinukaThejana",
		["email"] = "vinuka.t@pm.me",
		["password"] = "yoJEspLfqnbiylCyyNpGJNjcVNcfmXHmeujBCLFBEVxdXkJPwLmTECrjHZxiFeoM",
	},
}

local param1 = arg[1]
local param2 = arg[2]
local param3 = arg[3]

help({ param1, param2, param3 })

if not (param1 or param2 or param3) then
	local user = users[1]
	register(user["name"], user["username"], user["email"], user["password"])
	return
end

if param1 == "all" and param2 == "real" then
	for _, user in pairs(users) do
		register(user["name"], user["username"], user["email"], user["password"])
	end
	return
end

for _ = 1, 10, 1 do
	table.insert(users, {
		["name"] = faker:name(),
		["username"] = faker.randstring() .. faker.randint(2),
		["email"] = faker:email(),
		["password"] = faker.randstring() .. faker.randstring(),
	})
end

for _, user in pairs(users) do
	register(user["name"], user["username"], user["email"], user["password"])
end
