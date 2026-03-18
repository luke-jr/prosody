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
local function err(msg)
	import_errors = import_errors + 1;
	io.stderr:write("[error] "..msg.."\n");
end
local function info(msg)
	io.stderr:write("[info] "..msg.."\n");
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
	local Megaseconds,Seconds,Microseconds = unpack(tuple);
	if type(Megaseconds) ~= "number" or type(Seconds) ~= "number" then
		fatal("build_time: unexpected timestamp format: "..serialize(tuple));
	end
	local t = Megaseconds * 1000000 + Seconds;
	if Microseconds == nil then
		-- no microseconds field; that's fine
	elseif type(Microseconds) ~= "number" then
		fatal("build_time: unexpected microseconds type: "..type(Microseconds).." in "..serialize(tuple));
	elseif Microseconds > 0 then
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
			assert(password[5] == "sha", "unexpected passwd entry hash: "..tostring(password[5]));
			data.iteration_count = password[6];
		else
			assert(type(password[5]) == "number", "unexpected passwd entry in source data");
			data.iteration_count = password[5];
		end
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
		for _, item in pairs(items) do
			repeat
				if item[1] ~= "listitem" then err("privacy: unhandled item: "..tostring(item[1])); break; end
				local _type, value = item[2], item[3];
				if _type == "jid" then
					if type(value) ~= "table" then err("privacy: jid value is not valid: "..tostring(value)); break; end
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
		-- Bump any duplicate order values forward to maintain sorted order
		for i = 2, #list.items do
			if list.items[i].order <= list.items[i-1].order then
				warn("privacy: normalizing duplicate order value in list '"..tostring(name).."' for "..node.."@"..host);
				list.items[i].order = list.items[i-1].order + 1;
			end
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

	-- Inject implicit owner if not already present.
	-- CUSTOMIZE: replace this JID with the server admin for your deployment.
	local implicit_owner = "luke@dashjr.org";
	if not store._affiliations[implicit_owner] then
		store._affiliations[implicit_owner] = "owner";
		info("muc_room: injected implicit owner "..implicit_owner.." for "..node.."@"..host);
	end

	-- Robustly handle multiple subject formats seen in ejabberd dumps:
	-- 1. Empty list {} -> no subject
	-- 2. Direct string -> subject as-is
	-- 3. [{text, lang, text_value}] -> extract text_value (only single-item list expected)
	local subject_raw = properties.subject;
	if type(subject_raw) == "string" and subject_raw ~= "" then
		store._data.subject = subject_raw;
	elseif type(subject_raw) == "table" then
		if #subject_raw == 0 then
			-- empty list -> no subject
		elseif #subject_raw == 1 then
			local first = subject_raw[1];
			if type(first) == "table" and first[1] == "text"
			    and (first[2] == nil or type(first[2]) == "string")
			    and type(first[3]) == "string" then
				if first[3] ~= "" then store._data.subject = first[3]; end
			elseif type(first) == "string" and first ~= "" then
				store._data.subject = first;
			else
				warn("muc_room: unrecognized subject item format: "..serialize(first).." in "..node.."@"..host);
			end
		else
			-- Multiple items unexpected; use first text value and warn
			warn("muc_room: subject has "..#subject_raw.." items (expected 0 or 1); using first in "..node.."@"..host);
			local first = subject_raw[1];
			if type(first) == "table" and first[1] == "text"
			    and (first[2] == nil or type(first[2]) == "string")
			    and type(first[3]) == "string" then
				if first[3] ~= "" then store._data.subject = first[3]; end
			elseif type(first) == "string" and first ~= "" then
				store._data.subject = first;
			end
		end
	end

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

-- Table tracking rooms whose mam config says disabled, used for cross-check warnings
local muc_mam_disabled = {};

function archive_msg(us_node, us_host, id, t, peer, bare_peer, packet, nick, msg_type)
	-- msg_type is "chat" (personal MAM) or "groupchat" (MUC MAM / muc_log)
	local stanza = build_stanza(packet);
	local when = t;
	local item = st.preserialize(stanza);
	item.when = when;
	item.attr.stamp = os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(when));

	local store_user, store_host, store_name;
	if msg_type == "groupchat" then
		-- MUC MAM: stored by room node under muc_log
		store_user = us_node;
		store_host = us_host;
		store_name = "muc_log";
		if muc_mam_disabled[us_node.."@"..us_host] then
			warn("archive_msg: room "..us_node.."@"..us_host.." has mam=false but archive data exists; importing anyway");
			muc_mam_disabled[us_node.."@"..us_host] = nil; -- warn once
		end
		-- 'with' for MUC archive is the sender's bare JID
		item.with = build_jid(bare_peer, false);
		-- 'from' for MUC archive is the occupant JID (room@host/nick) when nick is known
		if type(nick) == "string" and nick ~= "" then
			item.attr.from = us_node.."@"..us_host.."/"..nick;
		end
	else
		-- Personal MAM: stored under the user's archive store
		store_user = us_node;
		store_host = us_host;
		store_name = "archive";
		item.with = build_jid(bare_peer, false);
	end

	item.key = id ~= "" and id or nil; -- use ejabberd id as key when available

	local ret, err = dm.list_append(store_user, store_host, store_name, item);
	print("["..(err or "success").."] archive_msg("..msg_type.."): "..store_user.."@"..store_host.." id="..tostring(id));
end

function archive_prefs(node, host, default_policy, always_jids, never_jids)
	-- default_policy is ejabberd atom: "always", "never", or "roster"
	local prefs = {};
	if default_policy == "always" then
		prefs[false] = true;
	elseif default_policy == "roster" then
		prefs[false] = "roster";
	else -- "never" or unknown -> never
		if default_policy ~= "never" then
			warn("archive_prefs: unknown default policy '"..tostring(default_policy).."' for "..node.."@"..host.."; treating as never");
		end
		prefs[false] = false;
	end
	for _, jid_tuple in ipairs(always_jids) do
		local jid = build_jid(jid_tuple, true);
		if jid then prefs[jid] = true; end
	end
	for _, jid_tuple in ipairs(never_jids) do
		local jid = build_jid(jid_tuple, true);
		if jid then prefs[jid] = false; end
	end
	local ret, err = dm.store(node, host, "archive_prefs", prefs);
	print("["..(err or "success").."] archive_prefs: "..node.."@"..host);
end

-- Pubsub import state:
-- Maps nodeidx (integer) -> { store_user, store_host, store_name, node_name, is_pep }
local pubsub_nodes_by_idx = {};
-- Pending items/states for nodes not yet seen, keyed by nodeidx
local pubsub_items_pending  = {};
local pubsub_states_pending = {};

local function pubsub_flush_pending(nodeidx)
	local node_info = pubsub_nodes_by_idx[nodeidx];
	if not node_info then return; end

	-- Flush pending items
	local pending_items = pubsub_items_pending[nodeidx];
	if pending_items then
		for _, item_data in ipairs(pending_items) do
			local ret, err = dm.list_append(node_info.store_user, node_info.store_host, node_info.store_name, item_data);
			print("["..(err or "success").."] pubsub_item (deferred): "..node_info.store_host.." node="..node_info.node_name.." id="..tostring(item_data.key));
		end
		pubsub_items_pending[nodeidx] = nil;
	end

	-- Flush pending states (affiliations/subscriptions merged into node config)
	local pending_states = pubsub_states_pending[nodeidx];
	if pending_states then
		local raw = dm.load(node_info.config_key, node_info.store_host, node_info.config_store) or {};
		local node_data = node_info.is_pep and (raw[node_info.node_name] or {}) or raw;
		for _, state in ipairs(pending_states) do
			local jid_str = state.jid;
			if state.affiliation and state.affiliation ~= "none" then
				node_data.affiliations = node_data.affiliations or {};
				node_data.affiliations[jid_str] = state.affiliation;
			end
			if state.subscription and state.subscription ~= "none" then
				node_data.subscribers = node_data.subscribers or {};
				node_data.subscribers[jid_str] = state.subscription;
			end
		end
		if node_info.is_pep then
			raw[node_info.node_name] = node_data;
			dm.store(node_info.config_key, node_info.store_host, node_info.config_store, raw);
		else
			dm.store(node_info.config_key, node_info.store_host, node_info.config_store, node_data);
		end
		pubsub_states_pending[nodeidx] = nil;
	end
end

function pubsub_node(nodeid_host, node_name, nodeidx, parents, ptype, owners, options)
	-- Determine if this is PEP (personal) or server pubsub
	local store_user, store_host, config_store, item_store, is_pep;
	if type(nodeid_host) == "table" then
		-- PEP node: nodeid_host = {user, host}
		is_pep = true;
		store_user = nodeid_host[1];
		store_host = nodeid_host[2];
		config_store = "pep";   -- map store, keyed by node_name
		item_store = "pep_"..node_name;
	else
		-- Server pubsub node: nodeid_host is a string (e.g. "pubsub.example.org")
		is_pep = false;
		store_user = node_name; -- node name is the "username" key in pubsub_nodes
		store_host = nodeid_host;
		config_store = "pubsub_nodes";
		item_store = "pubsub_"..node_name;
	end

	-- Build node config from ejabberd options list
	local config = {};
	if type(options) == "table" then
		for _, opt in ipairs(options) do
			if type(opt) == "table" and opt[1] then
				config[opt[1]] = opt[2];
			end
		end
	end

	-- Build affiliations from owners list
	local affiliations = {};
	if type(owners) == "table" then
		for _, owner in ipairs(owners) do
			local owner_jid = build_jid(owner, false);
			if owner_jid then affiliations[owner_jid] = "owner"; end
		end
	end

	local node_data = {
		name         = node_name;
		config       = config;
		subscribers  = {};
		affiliations = affiliations;
	};

	local ret, err;
	if is_pep then
		-- PEP: stored in map store "pep" under key=node_name for user
		local user_pep = dm.load(store_user, store_host, "pep") or {};
		user_pep[node_name] = node_data;
		ret, err = dm.store(store_user, store_host, "pep", user_pep);
	else
		-- Server pubsub: node name is the store key
		ret, err = dm.store(store_user, store_host, "pubsub_nodes", node_data);
	end
	print("["..(err or "success").."] pubsub_node: "..store_host.." node="..node_name);

	-- Register this node by idx for item/state lookup.
	-- item_user: nil for server pubsub (items keyed by nil), username for PEP.
	-- config_key: for server pubsub the node_name is the store key; for PEP it's the username.
	local item_user = is_pep and store_user or nil;
	local config_key = is_pep and store_user or node_name;
	pubsub_nodes_by_idx[nodeidx] = {
		store_user   = item_user;
		store_host   = store_host;
		store_name   = item_store;
		config_key   = config_key;
		config_store = config_store;
		node_name    = node_name;
		is_pep       = is_pep;
	};

	pubsub_flush_pending(nodeidx);
end

function pubsub_item(item_id, nodeidx, creation_ts, creation_jid, payload_list)
	local node_info = pubsub_nodes_by_idx[nodeidx];
	local publisher = type(creation_jid) == "table" and build_jid(creation_jid, true) or nil;
	local when = build_time(creation_ts);

	-- Build item as a preserialized stanza wrapper
	-- Items are stored as list entries with the payload as a stanza
	local payload_stanza;
	if type(payload_list) == "table" and #payload_list > 0 then
		payload_stanza = build_stanza(payload_list[1]);
	end

	local item_data;
	if payload_stanza then
		item_data = st.preserialize(payload_stanza);
	else
		item_data = { name = "item", attr = {}, tags = {}, last_add = {} };
	end
	item_data.when = when;
	item_data.with = publisher;
	item_data.key  = item_id;
	item_data.attr = item_data.attr or {};
	item_data.attr.stamp = os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(when));

	if node_info then
		local ret, err = dm.list_append(node_info.store_user, node_info.store_host, node_info.store_name, item_data);
		print("["..(err or "success").."] pubsub_item: "..node_info.store_host.." node="..node_info.node_name.." id="..tostring(item_id));
	else
		-- Node not yet seen; buffer for later
		pubsub_items_pending[nodeidx] = pubsub_items_pending[nodeidx] or {};
		table.insert(pubsub_items_pending[nodeidx], item_data);
	end
end

function pubsub_state(nodeidx, jid_tuple, item_ids, affiliation, subscriptions)
	if type(jid_tuple) ~= "table" then
		warn("pubsub_state: unexpected jid_tuple type for nodeidx "..tostring(nodeidx)..": "..serialize(jid_tuple)); return;
	end
	local jid_str = build_jid(jid_tuple, true);
	if not jid_str then
		warn("pubsub_state: could not build JID from "..serialize(jid_tuple)); return;
	end

	-- Normalize affiliation atom
	local aff = (affiliation ~= "none" and affiliation ~= "") and affiliation or nil;

	-- Extract first subscription type (if any)
	local sub = nil;
	if type(subscriptions) == "table" and #subscriptions > 0 then
		local first_sub = subscriptions[1];
		if type(first_sub) == "table" then
			sub = first_sub[1]; -- {subscription_type, sub_id}
		elseif type(first_sub) == "string" then
			sub = first_sub;
		end
		if sub == "none" then sub = nil; end
	end

	if not aff and not sub then return; end -- nothing to store

	local state_entry = { jid = jid_str, affiliation = aff, subscription = sub };

	local node_info = pubsub_nodes_by_idx[nodeidx];
	if node_info then
		-- Load and update node config
		local raw = dm.load(node_info.config_key, node_info.store_host, node_info.config_store) or {};
		local node_data = node_info.is_pep and (raw[node_info.node_name] or {}) or raw;
		if aff then
			node_data.affiliations = node_data.affiliations or {};
			node_data.affiliations[jid_str] = aff;
		end
		if sub then
			node_data.subscribers = node_data.subscribers or {};
			node_data.subscribers[jid_str] = sub;
		end
		if node_info.is_pep then
			raw[node_info.node_name] = node_data;
			dm.store(node_info.config_key, node_info.store_host, node_info.config_store, raw);
		else
			dm.store(node_info.config_key, node_info.store_host, node_info.config_store, node_data);
		end
		print("[success] pubsub_state: "..node_info.store_host.." node="..node_info.node_name.." jid="..jid_str);
	else
		pubsub_states_pending[nodeidx] = pubsub_states_pending[nodeidx] or {};
		table.insert(pubsub_states_pending[nodeidx], state_entry);
	end
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
		-- Track rooms with mam disabled for cross-check in archive_msg
		if properties.mam == "false" then
			local room_jid = tuple[2][1].."@"..tuple[2][2];
			muc_mam_disabled[room_jid] = true;
		end
		muc_room(tuple[2][1], tuple[2][2], properties);
	end;
	archive_msg = function(tuple)
		-- {archive_msg, {User,Host}, Id, Timestamp, Peer, BarePeer, Packet, Nick, Type}
		local us = tuple[2];
		if type(us) ~= "table" then fatal("archive_msg: unexpected us field: "..serialize(us)); end
		local id = tuple[3];
		local ts = tuple[4];
		if type(ts) ~= "table" then fatal("archive_msg: unexpected timestamp field: "..serialize(ts)); end
		local peer     = tuple[5];
		local bare_peer = tuple[6];
		local packet   = tuple[7];
		local nick     = tuple[8];
		local msg_type = tuple[9]; -- "chat" or "groupchat"
		if type(packet) ~= "table" then
			warn("archive_msg: skipping record with non-stanza packet for "..tostring(us[1]).."@"..tostring(us[2]).." id="..tostring(id));
			return;
		end
		archive_msg(us[1], us[2], id or "", build_time(ts), peer, bare_peer, packet, nick, msg_type or "chat");
	end;
	archive_prefs = function(tuple)
		-- {archive_prefs, {User,Host}, Default, Always, Never}
		local us = tuple[2];
		if type(us) ~= "table" then fatal("archive_prefs: unexpected us field: "..serialize(us)); end
		local default_policy = tuple[3] or "never";
		local always_jids    = tuple[4] or {};
		local never_jids     = tuple[5] or {};
		archive_prefs(us[1], us[2], default_policy, always_jids, never_jids);
	end;
	last_activity = function(tuple)
		-- {last_activity, {User,Host}, Timestamp, Status}
		local us = tuple[2];
		if type(us) ~= "table" then fatal("last_activity: unexpected us field: "..serialize(us)); end
		local node, host = us[1], us[2];
		local t = tuple[3];
		if type(t) ~= "number" then
			fatal("last_activity: unexpected timestamp type for "..tostring(node).."@"..tostring(host)..": "..serialize(t));
		end
		local status = tuple[4];
		if type(status) ~= "string" then status = ""; end
		-- Store into account_activity store (used by mod_account_activity)
		local ret, err = dm.store(node, host, "account_activity", { timestamp = t, status = status });
		print("["..(err or "success").."] last_activity: "..node.."@"..host);
	end;
	pubsub_node = function(tuple)
		-- {pubsub_node, {Host|{User,Host}, NodeId}, NodeIdx, Parents, Type, Owners, Options}
		local nodeid = tuple[2];
		if type(nodeid) ~= "table" then fatal("pubsub_node: unexpected nodeid: "..serialize(nodeid)); end
		local nodeid_host = nodeid[1];
		local node_name   = nodeid[2];
		local nodeidx     = tuple[3];
		if type(nodeidx) ~= "number" then fatal("pubsub_node: unexpected nodeidx: "..serialize(nodeidx)); end
		local parents = tuple[4] or {};
		local ptype   = tuple[5] or "";
		local owners  = tuple[6] or {};
		local options = tuple[7] or {};
		pubsub_node(nodeid_host, node_name, nodeidx, parents, ptype, owners, options);
	end;
	pubsub_item = function(tuple)
		-- {pubsub_item, {ItemId, NodeIdx}, {CreationTs, CreationJid}, {ModTs, ModJid}, Payload}
		local itemid_pair = tuple[2];
		if type(itemid_pair) ~= "table" then fatal("pubsub_item: unexpected itemid field: "..serialize(itemid_pair)); end
		local item_id = itemid_pair[1];
		local nodeidx = itemid_pair[2];
		if type(nodeidx) ~= "number" then fatal("pubsub_item: unexpected nodeidx: "..serialize(nodeidx)); end
		local creation = tuple[3];
		if type(creation) ~= "table" then fatal("pubsub_item: unexpected creation field: "..serialize(creation)); end
		local creation_ts  = creation[1];
		local creation_jid = creation[2];
		if type(creation_ts) ~= "table" then fatal("pubsub_item: unexpected creation timestamp: "..serialize(creation_ts)); end
		local payload_list = tuple[5] or {};
		pubsub_item(item_id, nodeidx, creation_ts, creation_jid, payload_list);
	end;
	pubsub_state = function(tuple)
		-- {pubsub_state, {NodeIdx, {User,Host,Resource}}, Items, Affiliation, Subscriptions}
		local stateid = tuple[2];
		if type(stateid) ~= "table" then fatal("pubsub_state: unexpected stateid: "..serialize(stateid)); end
		local nodeidx   = stateid[1];
		local jid_tuple = stateid[2];
		if type(nodeidx) ~= "number" then fatal("pubsub_state: unexpected nodeidx: "..serialize(nodeidx)); end
		local item_ids      = tuple[3] or {};
		local affiliation   = tuple[4] or "none";
		local subscriptions = tuple[5] or {};
		pubsub_state(nodeidx, jid_tuple, item_ids, affiliation, subscriptions);
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

-- Flush any pubsub items/states that were buffered waiting for their node
local pending_item_count = 0;
local pending_state_count = 0;
local missing_nodeids = {};
for nodeidx, items in pairs(pubsub_items_pending) do
	pending_item_count = pending_item_count + #items;
	missing_nodeids[nodeidx] = true;
end
for nodeidx, states in pairs(pubsub_states_pending) do
	pending_state_count = pending_state_count + #states;
	missing_nodeids[nodeidx] = true;
end
if pending_item_count > 0 or pending_state_count > 0 then
	local idx_list = {};
	for idx in pairs(missing_nodeids) do idx_list[#idx_list+1] = tostring(idx); end
	table.sort(idx_list);
	err(("pubsub: %d item(s) and %d state(s) reference unknown node index(es) [%s] and could not be imported"):format(
		pending_item_count, pending_state_count, table.concat(idx_list, ", ")));
end

print(("\nImport complete: %d records processed, %d warnings, %d errors."):format(count, import_warnings, import_errors));
--print(serialize(t));
