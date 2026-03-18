#!/usr/bin/env lua
-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--



package.path = package.path ..";../?.lua";

local my_name = arg[0];
if my_name:match("[/\\]") then
	package.path = package.path..";"..my_name:gsub("[^/\\]+$", "../?.lua");
	package.path = package.path..";"..my_name:gsub("[^/\\]+$", "?.lua");
	package.cpath = package.cpath..";"..my_name:gsub("[^/\\]+$", "../?.so");
end

local erlparse = require "erlparse";

prosody = {};

package.loaded["util.logger"] = {init = function() return function() end; end}
local serialize = require "util.serialization".serialize;
local st = require "util.stanza";
local dm = require "util.datamanager"
dm.set_data_path("data");

-- Diagnostics helpers
local import_warnings = 0;
local import_errors   = 0;
local function warn(msg)
	import_warnings = import_warnings + 1;
	io.stderr:write("[warn] "..msg.."\n");
end
local function fatal(msg)
	import_errors = import_errors + 1;
	error("[fatal] "..msg, 2);
end

function build_stanza(tuple, stanza)
	assert(type(tuple) == "table", "XML node is of unexpected type: "..type(tuple));
	if tuple[1] == "xmlelement" or tuple[1] == "xmlel" then
		assert(type(tuple[2]) == "string", "element name has type: "..type(tuple[2]));
		assert(type(tuple[3]) == "table", "element attribute array has type: "..type(tuple[3]));
		assert(type(tuple[4]) == "table", "element children array has type: "..type(tuple[4]));
		local name = tuple[2];
		local attr = {};
		for _, a in ipairs(tuple[3]) do
			if type(a[1]) == "string" and type(a[2]) == "string" then attr[a[1]] = a[2]; end
		end
		local up;
		if stanza then stanza:tag(name, attr); up = true; else stanza = st.stanza(name, attr); end
		for _, a in ipairs(tuple[4]) do build_stanza(a, stanza); end
		if up then stanza:up(); else return stanza end
	elseif tuple[1] == "xmlcdata" then
		if type(tuple[2]) ~= "table" then
			assert(type(tuple[2]) == "string", "XML CDATA has unexpected type: "..type(tuple[2]));
			stanza:text(tuple[2]);
		end -- else it's [], i.e., the null value, used for the empty string
	else
		error("unknown element type: "..serialize(tuple));
	end
end
function build_time(tuple)
	local Megaseconds, Seconds, Microseconds = unpack(tuple);
	if type(Megaseconds) ~= "number" or type(Seconds) ~= "number" then
		fatal("build_time: unexpected timestamp format: "..serialize(tuple));
	end
	local t = Megaseconds * 1000000 + Seconds;
	if type(Microseconds) == "number" and Microseconds > 0 then
		t = t + Microseconds / 1000000;
	end
	return t;
end
function build_jid(tuple, full)
	local node, jid, resource = tuple[1], tuple[2], tuple[3]
	if type(node) == "string" and node ~= "" then
		jid = tuple[1] .. "@" .. jid;
	end
	if full and type(resource) == "string" and resource ~= "" then
		jid = jid .. "/" .. resource;
	end
	return jid;
end

function vcard(node, host, stanza)
	local ret, err = dm.store(node, host, "vcard", st.preserialize(stanza));
	print("["..(err or "success").."] vCard: "..node.."@"..host);
end
function password(node, host, password)
	local data = {};
	if type(password) == "string" then
		data.password = password;
	elseif type(password) == "table" and password[1] == "scram" then
		local unb64 = require"mime".unb64;
		local function hex(s)
			return s:gsub(".", function (c)
				return ("%02x"):format(c:byte());
			end);
		end
		data.stored_key = hex(unb64(password[2]));
		data.server_key = hex(unb64(password[3]));
		data.salt = unb64(password[4]);
		if type(password[6]) == "number" then
			if password[5] ~= "sha" then
				fatal("passwd: unexpected SCRAM hash algorithm: "..tostring(password[5]).." for "..node.."@"..host);
			end
			data.iteration_count = password[6];
		elseif type(password[5]) == "number" then
			data.iteration_count = password[5];
		else
			fatal("passwd: unexpected SCRAM iteration_count fields for "..node.."@"..host..": "..serialize(password));
		end
	else
		fatal("passwd: unexpected password/auth shape for "..node.."@"..host..": "..serialize(password));
	end
	local ret, err = dm.store(node, host, "accounts", data);
	print("["..(err or "success").."] accounts: "..node.."@"..host);
end
function roster(node, host, jid, item)
	local roster = dm.load(node, host, "roster") or {};
	roster[jid] = item;
	local ret, err = dm.store(node, host, "roster", roster);
	print("["..(err or "success").."] roster: " ..node.."@"..host.." - "..jid);
end
function roster_pending(node, host, jid)
	local roster = dm.load(node, host, "roster") or {};
	roster.pending = roster.pending or {};
	roster.pending[jid] = true;
	local ret, err = dm.store(node, host, "roster", roster);
	print("["..(err or "success").."] roster: " ..node.."@"..host.." - "..jid);
end
function private_storage(node, host, xmlns, stanza)
	local private = dm.load(node, host, "private") or {};
	private[stanza.name..":"..xmlns] = st.preserialize(stanza);
	local ret, err = dm.store(node, host, "private", private);
	print("["..(err or "success").."] private: " ..node.."@"..host.." - "..xmlns);
end
function offline_msg(node, host, t, stanza)
	stanza.attr.stamp = os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(t));
	stanza.attr.stamp_legacy = os.date("!%Y%m%dT%H:%M:%S", math.floor(t));
	local ret, err = dm.list_append(node, host, "offline", st.preserialize(stanza));
	print("["..(err or "success").."] offline: " ..node.."@"..host.." - "..os.date("!%Y-%m-%dT%H:%M:%SZ", t));
end
function privacy(node, host, default, lists)
	local privacy = { lists = {} };
	local count = 0;
	if default then privacy.default = default; end
	for _, inlist in ipairs(lists) do
		local name, items = inlist[1], inlist[2];
		local list = { name = name; items = {}; };
		local orders = {};
		for _, item in pairs(items) do
			repeat
				if item[1] ~= "listitem" then warn("privacy: unhandled item: "..tostring(item[1])); break; end
				local _type, value = item[2], item[3];
				if _type == "jid" then
					if type(value) ~= "table" then warn("privacy: jid value is not valid: "..tostring(value)); break; end
					value = build_jid(value, true)
				elseif _type == "none" then
					_type = nil;
					value = nil;
				elseif _type == "group" then
					if type(value) ~= "string" then warn("privacy: group value is not string: "..tostring(value)); break; end
				elseif _type == "subscription" then
					if value~="both" and value~="from" and value~="to" and value~="none" then
						warn("privacy: subscription value is invalid: "..tostring(value)); break;
					end
				else warn("privacy: invalid item type: "..tostring(_type)); break; end
				local action = item[4];
				if action ~= "allow" and action ~= "deny" then warn("privacy: unhandled action: "..tostring(action)); break; end
				local order = item[5];
				if type(order) ~= "number" or order<0 then warn("privacy: order is not numeric: "..tostring(order)); break; end
				local match_all = item[6];
				local match_iq = item[7];
				local match_message = item[8];
				local match_presence_in = item[9];
				local match_presence_out = item[10];
				list.items[#list.items+1] = {
					type = _type;
					value = value;
					action = action;
					order = order;
					message = match_message == "true";
					iq = match_iq == "true";
					["presence-in"] = match_presence_in == "true";
					["presence-out"] = match_presence_out == "true";
				};
			until true;
		end
		table.sort(list.items, function(a, b) return a.order < b.order; end);
		-- Detect and normalize duplicate order values by renumbering sequentially
		local has_dupes = false;
		for i = 2, #list.items do
			if list.items[i].order == list.items[i-1].order then has_dupes = true; break; end
		end
		if has_dupes then
			warn("privacy: normalizing duplicate order values in list '"..tostring(name).."' for "..node.."@"..host);
			for i, li in ipairs(list.items) do li.order = i; end
		end
		if privacy.lists[list.name] then warn("privacy: duplicate privacy list: "..tostring(list.name)); end
		privacy.lists[list.name] = list;
		count = count + 1;
	end
	if default and not privacy.lists[default] then
		if default == "none" then privacy.default = nil;
		else warn("privacy: default privacy list doesn't exist: "..tostring(default)); end
	end
	local ret, err = dm.store(node, host, "privacy", privacy);
	print("["..(err or "success").."] privacy: " ..node.."@"..host.." - "..count.." list(s)");
end
function muc_room(node, host, properties)
	local store = { jid = node.."@"..host, _data = {}, _affiliations = {} };
	for _,aff in ipairs(properties.affiliations) do
		store._affiliations[build_jid(aff[1])] = aff[2][1] or aff[2];
	end

	-- Inject implicit owner if not already present
	local implicit_owner = "luke@dashjr.org";
	if not store._affiliations[implicit_owner] then
		store._affiliations[implicit_owner] = "owner";
		warn("muc_room: injected implicit owner "..implicit_owner.." for "..node.."@"..host);
	end

	-- Robustly handle multiple subject formats seen in ejabberd dumps:
	-- 1. Empty list {} -> no subject
	-- 2. Direct string -> subject as-is
	-- 3. [{text, lang, text_value}] -> extract text_value
	local subject_raw = properties.subject;
	if type(subject_raw) == "string" and subject_raw ~= "" then
		store._data.subject = subject_raw;
	elseif type(subject_raw) == "table" and #subject_raw > 0 then
		local first = subject_raw[1];
		if type(first) == "table" and first[1] == "text" and type(first[3]) == "string" then
			if first[3] ~= "" then store._data.subject = first[3]; end
		elseif type(first) == "string" and first ~= "" then
			store._data.subject = first;
		else
			warn("muc_room: unrecognized subject item format: "..serialize(first).." in "..node.."@"..host);
		end
	end -- else: empty table -> no subject

	if properties.subject_author and properties.subject_author ~= "" then
		store._data.subject_from = store.jid .. "/" .. properties.subject_author;
	end
	store._data.name = properties.title;
	store._data.description = properties.description;
	if properties.password_protected ~= false and properties.password ~= "" then
		store._data.password = properties.password;
	end
	store._data.moderated = (properties.moderated == "true") or nil;
	store._data.members_only = (properties.members_only == "true") or nil;
	store._data.persistent = (properties.persistent == "true") or nil;
	store._data.changesubject = (properties.allow_change_subj == "true") or nil;
	store._data.whois = properties.anonymous == "true" and "moderators" or "anyone";
	store._data.hidden = (properties.public_list == "false") or nil;

	if not store._data.persistent then
		warn("muc_room: skipping non-persistent room: "..node.."@"..host);
		return;
	end

	local ret, err = dm.store(node, host, "config", store);
	if ret then
		ret, err = dm.load(nil, host, "persistent");
		if ret or not err then
			ret = ret or {};
			ret[store.jid] = true;
			ret, err = dm.store(nil, host, "persistent", ret);
		end
	end
	print("["..(err or "success").."] muc_room: " ..node.."@"..host);
end


local filters = {
	passwd = function(tuple)
		password(tuple[2][1], tuple[2][2], tuple[3]);
	end;
	vcard = function(tuple)
		vcard(tuple[2][1], tuple[2][2], build_stanza(tuple[3]));
	end;
	roster = function(tuple)
		local node = tuple[3][1]; local host = tuple[3][2];
		local contact = build_jid(tuple[4]);
		local name = tuple[5]; local subscription = tuple[6];
		local ask = tuple[7]; local groups = tuple[8];
		if type(name) ~= type("") then name = nil; end
		if ask == "none" then
			ask = nil;
		elseif ask == "out" then
			ask = "subscribe"
		elseif ask == "in" then
			roster_pending(node, host, contact);
			ask = nil;
		elseif ask == "both" then
			roster_pending(node, host, contact);
			ask = "subscribe";
		else error("Unknown ask type: "..ask); end
		if subscription ~= "both" and subscription ~= "from" and subscription ~= "to" and subscription ~= "none" then error(subscription) end
		local item = {name = name, ask = ask, subscription = subscription, groups = {}};
		for _, g in ipairs(groups) do
			if type(g) == "string" then
				item.groups[g] = true;
			end
		end
		roster(node, host, contact, item);
	end;
	private_storage = function(tuple)
		private_storage(tuple[2][1], tuple[2][2], tuple[2][3], build_stanza(tuple[3]));
	end;
	offline_msg = function(tuple)
		offline_msg(tuple[2][1], tuple[2][2], build_time(tuple[3]), build_stanza(tuple[7]));
	end;
	privacy = function(tuple)
		privacy(tuple[2][1], tuple[2][2], tuple[3], tuple[4]);
	end;
	muc_room = function(tuple)
		local properties = {};
		for _,pair in ipairs(tuple[3]) do
			if not(type(pair[2]) == "table" and #pair[2] == 0) then -- skip nil values
				properties[pair[1]] = pair[2];
			end
		end
		muc_room(tuple[2][1], tuple[2][2], properties);
	end;
	--[=[config = function(tuple)
		if tuple[2] == "hosts" then
			local output = io.output(); io.output("prosody.cfg.lua");
			io.write("-- Configuration imported from ejabberd --\n");
			io.write([[Host "*"
	modules_enabled = {
		"saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
		"legacyauth"; -- Legacy authentication. Only used by some old clients and bots.
		"roster"; -- Allow users to have a roster. Recommended ;)
		"register"; -- Allow users to register on this server using a client
		"tls"; -- Add support for secure TLS on c2s/s2s connections
		"vcard"; -- Allow users to set vCards
		"private"; -- Private XML storage (for room bookmarks, etc.)
		"version"; -- Replies to server version requests
		"dialback"; -- s2s dialback support
		"uptime";
		"disco";
		"time";
		"ping";
		--"selftests";
	};
]]);
			for _, h in ipairs(tuple[3]) do
				io.write("Host \"" .. h .. "\"\n");
			end
			io.output(output);
			print("prosody.cfg.lua created");
		end
	end;]=]
};

local arg = ...;
local help = "/? -? ? /h -h /help -help --help";
if not arg or help:find(arg, 1, true) then
	print([[ejabberd db dump importer for Prosody

  Usage: ]]..my_name..[[ filename.txt

The file can be generated from ejabberd using:
  sudo ejabberdctl dump filename.txt

Note: The path of ejabberdctl depends on your ejabberd installation, and ejabberd needs to be running for ejabberdctl to work.]]);
	os.exit(1);
end
local count = 0;
local t = {};
for item in erlparse.parseFile(arg) do
	count = count + 1;
	local name = item[1];
	t[name] = (t[name] or 0) + 1;
	--print(count, serialize(item));
	if filters[name] then
		local ok, err = pcall(filters[name], item);
		if not ok then io.stderr:write(tostring(err).."\n"); end
	end
end
print(("\nImport complete: %d records processed, %d warnings, %d errors."):format(count, import_warnings, import_errors));
--print(serialize(t));
