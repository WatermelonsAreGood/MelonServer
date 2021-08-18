#include "server.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <vector>

/* sha1 hashing */
#include <openssl/sha.h>

#ifdef UWS_UDS
#include <sys/types.h>
#include <sys/stat.h>
#endif

static const char* hexmap = "0123456789abcdef";
static uint32_t defClr = 0xFF7F00;

uint32_t getDefaultRoomColor() {
	return defClr;
}

size_t getUTF8strlen(const std::string& str){
	size_t j = 0, i = 0, x = 1;
	while (i < str.size()) {
		if (x > 4) /* Invalid unicode */
			return SIZE_MAX;

		if ((str[i] & 0xC0) != 0x80){
			j += x == 4 ? 2 : 1;
			x = 1;
		} else {
			x++;
		}
		i++;
	}
	if(x == 4)
		j++;
	return (j);
}

std::string getSocketIp(uS::Socket * s, uWS::HttpRequest req) {
	auto addr = s->getAddress();
	switch (addr.family[3]) {
		case '6':
		case '4':
			uWS::Header cf = req.getHeader("cf-connecting-ip");
			uWS::Header xf = req.getHeader("X-Forwarded-For");
			
			return cf ? cf.toString() : xf.toString();
			break;

#ifdef UWS_UDS
		case 'X': {
			uWS::Header h = req.getHeader("x-real-ip", 9);
			return h ? h.toString() : "";
		} break;
#endif
	}

	return "";
}

std::string roundfloat(const float x, int prec){
	std::stringstream ss;
	ss << std::fixed << std::setprecision(prec) << x;
	return ss.str();
}

std::string n2hexstr(uint32_t w, bool alpha = false) {
    const uint8_t l = alpha ? 32 : 24;
    std::string rc(l/4, '0');
    for (uint8_t i = 0, x = l/4-1; i < l; x--, i += 4)
        rc[x] = hexmap[(w>>i) & 0x0f];
    return rc;
}

int64_t js_date_now(){
	namespace c = std::chrono;

	auto time = c::system_clock::now().time_since_epoch();
	return c::duration_cast<c::milliseconds>(time).count();
}

nlohmann::json server::Room::get_json(std::string _id, bool includeppl){
	nlohmann::json j = {
		{"m", "ch"},
		{"ch", {
			{"_id", _id},
			{"count", ids.size()},
			{"settings", {
				{"visible", visible},
				{"chat", chat},
				{"lobby", lobby},
				{"crownsolo", crownsolo},
				{"color", std::string("#")+n2hexstr(color)}
			}}
		}}
	};
	if(includeppl){
		if(!lobby){
			if(crown.owner){
				auto search = ids.find(crown.owner);
				if(search != ids.end()){
					j["ch"]["crown"] = {
						{"participantId", search->second.id},
						{"userId", search->first->get_json()["_id"]}
					};
				}
			} else {
				j["ch"]["crown"] = {
					{"time", crown.time},
					{"startPos", {
						{"x", roundfloat(crown.startpos[0], 2)},
						{"y", roundfloat(crown.startpos[1], 2)}
					}},
					{"endPos", {
						{"x", roundfloat(crown.endpos[0], 2)},
						{"y", roundfloat(crown.endpos[1], 2)}
					}}
				};
			}
		}
		auto ppl = nlohmann::json::array();
		for(auto& c : ids){
			auto inf = c.first->get_json();
			inf["x"] = roundfloat(c.second.x, 2);
			inf["y"] = roundfloat(c.second.y, 2);
			inf["id"] = c.second.id;
			ppl.push_back(inf);
		}
		j["ppl"] = ppl;
	}
	return j;
}

nlohmann::json server::Room::get_chatlog_json(){
	nlohmann::json log = nlohmann::json::array();
	for(auto& msg : chatlog){
		log.push_back(msg);
	}
	return log;
}

void server::Room::push_chat(nlohmann::json& j){
	chatlog.push_back(j);
	if(chatlog.size() > 32)
		chatlog.pop_front();
}

nlohmann::json server::Client::get_json(){
	return nlohmann::json::object({
		{"name", name},
		{"color", std::string("#")+n2hexstr(color)},
		{"_id", _id},
		{"tag", tag}
	});
}

server::Database::pinfo_t server::Client::get_dbdata(){
	return {true, color, name, tag};
}

void server::Room::broadcast(nlohmann::json& j, uWS::WebSocket<uWS::SERVER> * exclude){
	uWS::WebSocket<uWS::SERVER>::PreparedMessage* prep = uWS::WebSocket<uWS::SERVER>::prepareMessage(
		(char *)j.dump().c_str(), j.dump().size(), uWS::TEXT, false);
	for(auto& c : ids){
		for(auto sock : c.second.sockets){
			if(sock == exclude) continue;
			sock->sendPrepared(prep);
		}
	}
	uWS::WebSocket<uWS::SERVER>::finalizeMessage(prep);
}

void server::Room::broadcast(const char* j, uWS::WebSocket<uWS::SERVER> * exclude, size_t len){
	uWS::WebSocket<uWS::SERVER>::PreparedMessage* prep = uWS::WebSocket<uWS::SERVER>::prepareMessage(
		(char*)j, len, uWS::BINARY, false);
	for(auto& c : ids){
		for(auto sock : c.second.sockets){
			if(sock == exclude) continue;
			sock->sendPrepared(prep);
		}
	}
	uWS::WebSocket<uWS::SERVER>::finalizeMessage(prep);
}

void server::Room::part_upd(Client* c){
	auto search = ids.find(c);
	if(search != ids.end()){
		nlohmann::json j = nlohmann::json::array();
		j[0] = c->get_json();
		j[0]["id"] = search->second.id;
		j[0]["m"] = "p";
		this->broadcast(j, nullptr);
	}
}

clinfo_t* server::Room::get_info(Client* c){
	auto search = ids.find(c);
	if(search != ids.end()){
		return &search->second;
	}
	return nullptr;
}

void server::Room::set_param(nlohmann::json& j, std::string _id){
	bool updated = false;
	bool nvisible = visible;
	bool nchat = chat;
	bool ncrownsolo = crownsolo;
	uint32_t ncolor = color;
	if(j["visible"].is_boolean()){
		nvisible = j["visible"].get<bool>();
		if(nvisible != visible) updated = true;
	}
	if(j["chat"].is_boolean()){
		nchat = j["chat"].get<bool>();
		if(nchat != chat) updated = true;
	}
	if(j["crownsolo"].is_boolean()){
		ncrownsolo = j["crownsolo"].get<bool>();
		if(ncrownsolo != crownsolo) updated = true;
	}
	if(j["color"].is_string()){
		std::string strcolor = j["color"].get<std::string>();
		if(strcolor.size() > 1 && strcolor[0] == '#'){
			strcolor.erase(0, 1);
			try {
				ncolor = std::stoul(std::string("0x") + strcolor, nullptr, 16);
			} catch(const std::invalid_argument&) { return; }
			  catch(const std::out_of_range&) { return; }
		}
		if(ncolor != color) updated = true;
	}
	if(updated){
		color = ncolor;
		visible = nvisible;
		crownsolo = ncrownsolo;
		chat = nchat;
		nlohmann::json j2 = nlohmann::json::array();
		j2[0] = this->get_json(_id, true);
		this->broadcast(j2, nullptr);
	}
}

void server::Room::set_owner(Client* c){
	float x = 50;
	float y = 50;
	auto search = ids.find(crown.owner);
	if(!c && search != ids.end()){
		x = search->second.x;
		y = search->second.y;
	}
	/* the ternary makes sure the crown doesn't land off the screen */
	crown = {c, crown.owner, {x, y}, {x > 95 ? 95 : x < 5 ? 5 : x, y+25 > 95 ? 95 : y+25 < 5 ? 5 : y+25}, js_date_now()};
}

server::Client* server::Room::get_client(std::string id){
	for(auto c : ids)
		if(c.second.id == id)
			return c.first;
	return nullptr;
}

server::Client* server::Room::get_client_id(std::string _id){
	for (auto c : ids)
		if (c.first->_id == _id)
			return c.first;
	
	return nullptr;
}

bool server::Room::kick_usr(uWS::WebSocket<uWS::SERVER> * s, mppconn_t& c, std::string rname){
	std::string ip = *(std::string *) s->getUserData();
	bool ownupd = false;
	auto ssearch = ids.find(c.user);
	if(ssearch != ids.end()){
		if(ssearch->second.sockets.erase(s) && !ssearch->second.sockets.size()){
			if(!lobby && c.user == crown.owner){
				ownupd = true;
				this->set_owner(nullptr);
			}
			std::string id = ssearch->second.id;
			ids.erase(c.user);
			if(!ids.size()){
				return true;
			}
			/* Client left room, notify.
			 * Don't send the first if owner changed because we need
			 * to send the complete room data, and doing this would
			 * waste some bandwidth.
			 ***/
			if(!ownupd){
				nlohmann::json j = nlohmann::json::array();
				j[0] = {
					{"m", "bye"},
					{"p", id}
				};
				this->broadcast(j, s);
			} else {
				nlohmann::json j = nlohmann::json::array();
				j[0] = this->get_json(rname, true);
				this->broadcast(j, s);
			}
		}
	}
	return false;
}

jroom_clinfo_t server::Room::join_usr(uWS::WebSocket<uWS::SERVER> * s, mppconn_t& c, std::string rname){
	auto search = ids.find(c.user);
	std::string id;
	bool newclient;
	if(search == ids.end()){
		/* TODO: generate better id? */
		id = std::to_string(js_date_now());
		ids[c.user] = {std::set<uWS::WebSocket<uWS::SERVER> *>{s}, {}, id, -10, -10};
		newclient = true;
	} else {
		search->second.sockets.emplace(s);
		id = search->second.id;
		newclient = false;
	}
	c.sockets.at(s) = rname;
	return {id, newclient};
}

void server::user_upd(server::mppconn_t& c){
	/* a set so we don't update the same room twice */
	std::set<Room*> roomstoupdate;
	c.user->changed = true;
	for(auto& sock : c.sockets){
		auto search = rooms.find(sock.second);
		if(search != rooms.end()){
			roomstoupdate.emplace(search->second);
		}
	}
	for(auto r : roomstoupdate){
		r->part_upd(c.user);
	}
}

nlohmann::json server::get_roomlist(){
	nlohmann::json res = nlohmann::json::array();
	for(auto room : rooms){
		nlohmann::json j = room.second->get_json(room.first, false)["ch"]; /* ugly */
		if(j["settings"]["visible"].get<bool>()){
			res.push_back(j);
		}
	}
	return res;
}

jroom_clinfo_t server::set_room(std::string newroom, uWS::WebSocket<uWS::SERVER> * s, mppconn_t& m, nlohmann::json& set){
	auto thissocket = m.sockets.find(s);
	if(thissocket != m.sockets.end() && thissocket->second != newroom){
		auto old = rooms.find(thissocket->second);

		if(old != rooms.end()){
			bool isempty = old->second->kick_usr(s, m, old->first);
			if(old->second->is_visible())
				rooml_upd(old->second, old->first);
			if(isempty){
				std::cout << "Deleted room: " << old->first << std::endl;
				delete old->second;
				rooms.erase(old);
			}
		}
		auto newr = rooms.find(newroom);
		Room* room;
		if(newr == rooms.end()){
			bool islobby = !newroom.compare(0, 5, "lobby") || !newroom.compare(0, 5, "test/");
			std::cout << "Created new room: " << newroom << std::endl;
			rooms.emplace(newroom, new server::Room(islobby));
			room = rooms[newroom];
			if(!islobby) {
				room->set_param(set, newroom);
				room->set_owner(m.user);
			}
		} else {
			room = newr->second;
		}
		jroom_clinfo_t info = room->join_usr(s, m, newroom);
		if(room->is_visible())
			rooml_upd(room, newroom);
		return info;
	}
	return {"null", false};
}

void server::rooml_upd(Room* r, std::string _id){
	if(roomlist_watchers.size()){
		nlohmann::json res = nlohmann::json::array();
		res[0] = {
			{"m", "ls"},
			{"c", false},
			{"u", nlohmann::json::array()}
		};
		res[0]["u"][0] = r->get_json(_id, false)["ch"];
		for(auto sock : roomlist_watchers){
			sock->send((char *)res.dump().c_str(), res.dump().size(), uWS::TEXT);
		}
	}
}

// TODO: This doesn't check for errors. Like at all.
// It doesn't care. Seriously.

std::string sha256(std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
	SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
	return ss.str();
}

nlohmann::json server::genusr(uWS::WebSocket<uWS::SERVER> * s){
	std::string ip = *(std::string *) s->getUserData();
	auto search = clients.find(ip);
	if(search == clients.end()){
		std::string saltedip(ip + this->salt);

		std::string name("(=^ェ^=)");
		std::string _id = sha256(saltedip);

		_id.resize(24);
		
		uint32_t color = (uint32_t)_id[0] << 24 |
		                 (uint32_t)_id[1] << 16 |
		                 (uint16_t)_id[2] << 8 |
		                           _id[3];

		std::string tag = "";
		server::Database::pinfo_t dbusr = db.get_usrinfo(_id);

		if(dbusr.found){
			color = dbusr.color;
			name = dbusr.name;
			tag = dbusr.tag;
		}
		
		std::vector<std::string> admins = this->admins;

		std::cout << "New client" << (std::count(admins.begin(), admins.end(), ip) ? " (admin)" : "") << ": " << ip << std::endl;

		clients[ip] = {new server::Client(_id, color, name, std::count(admins.begin(), admins.end(), ip), tag, ip), {{s, ""}}};
	} else {
		search->second.sockets.emplace(s, "");
	}
	return clients[ip].user->get_json();
}

void server::run(){
#ifdef UWS_UDS
	auto m = umask(7);
#endif
	if (!h.listen(path.c_str(), port)) {
		std::cerr << "Can't listen on:" << path << ":" << port << std::endl;
		return;
	}
#ifdef UWS_UDS
	umask(m);
#endif
	reg_evts(h);
	h.run();
}

void server::reg_evts(uWS::Hub &s){
	s.onConnection([this](uWS::WebSocket<uWS::SERVER> * socket, uWS::HttpRequest req){
		socket->setUserData(new std::string(getSocketIp(socket, req)));
	});

	s.onDisconnection([this](uWS::WebSocket<uWS::SERVER> * socket, int c, const char *message, size_t length){
		std::string ip = *(std::string *) socket->getUserData();
		roomlist_watchers.erase(socket);
		auto search = clients.find(ip);
		if(search != clients.end()){
			auto ssearch = search->second.sockets.find(socket);
			if(ssearch != search->second.sockets.end()){
				auto tsearch = rooms.find(ssearch->second);
				if(tsearch != rooms.end() && tsearch->second->kick_usr(socket, search->second, tsearch->first)){
					std::cout << "Deleted room: " << tsearch->first << std::endl;
					delete tsearch->second;
					rooms.erase(tsearch);
				}
				search->second.sockets.erase(socket);
			}
			if(!search->second.sockets.size()){
				if(search->second.user->changed){
					std::cout << "Saving client." << std::endl;
					db.set_usrinfo(search->second.user->_id,
						       search->second.user->get_dbdata());
				}
				std::cout << "Deleted client: " << ip << std::endl;
				delete search->second.user;
				clients.erase(ip);
			}
		}
		delete (std::string *) socket->getUserData();
	});

	s.onMessage([this](uWS::WebSocket<uWS::SERVER> * socket, const char *message, size_t length, uWS::OpCode opCode){
#ifndef VANILLA_SERVER
		if(opCode == uWS::BINARY && length > 1){
			switch((uint8_t)message[0]){
				case 1:
					msg::bin_n(this, message, length, socket);
					break;
				default:
					socket->close();
					return;
					break;
			}
		} else
#endif
		if(opCode == uWS::TEXT) try {
			auto msg = nlohmann::json::parse(std::string(message, length));
			if(msg.is_array())
				parse_msg(msg, socket);
		} catch(...) { /* just catch everything */
			/* kick his ass */
			socket->close();
			return;
		} else {
			socket->close();
			return;
		}
	});

	h.getDefaultGroup<uWS::SERVER>().startAutoPing(30000);
}

void server::parse_msg(nlohmann::json& msg, uWS::WebSocket<uWS::SERVER> * socket){
	for(auto& m : msg){
		if(m.is_object() && m["m"].is_string()){
			std::string currmsg(m["m"].get<std::string>());
			/* we don't want to continue reading messages if the client said bye */
			if(currmsg == "bye"){
				socket->close();
				break;
			}

			auto clsearch = clients.find(*(std::string *) socket->getUserData());
			if((clsearch == clients.end() || clsearch->second.sockets.find(socket) == clsearch->second.sockets.end())
					&& currmsg != "hi") {
				socket->close();
				break;
			}

			auto str = funcmap.find(currmsg);
			if(str != funcmap.end()){
				str->second(m, socket);
			}
		}
	}
}

nlohmann::json getConfig() {
	std::ifstream i("config.json");
	nlohmann::json j;

	if(i.good()) {
		i >> j;
	} else {
		std::cout << "could not find config.json - quitting";
		std::exit(0);
	}
	
	return j;
}

int main(int argc, char *argv[]){
	nlohmann::json config = getConfig();

	std::string addr = "0.0.0.0";
	std::string pass = "fuckthisshit";
	std::string salt = "I HAVE PRESIDENTIAL AIDS";
	std::vector<std::string> admins = config["admins"];

	int port = 20005;
	
	if(config.contains("addr")) addr = config["addr"];
	if(config.contains("pass")) pass = config["pass"];
	if(config.contains("salt")) salt = config["salt"];
	if(config.contains("port")) port = config["port"];

	std::cout << "Listening on " + addr + ":" << port << "!" << std::endl;
	std::cout << "APass length: " << pass.length() << "!" << std::endl;
	std::cout << "Salt length: " << salt.length() << "!" << std::endl;

	server s(addr, port, pass, salt, admins);
	s.run();
	return 1;
}
