#include "server.hpp"
#include <iostream>
#include <string>

server::Database::pinfo_t server::Database::get_usrinfo(std::string hash){
	
	std::ifstream people_file(dir + hash, std::ifstream::binary);
	server::Database::pinfo_t ret = {false, 0, {}};

	if(people_file.good()) {
		ret.found = true;

		std::string str((std::istreambuf_iterator<char>(people_file)),
                 std::istreambuf_iterator<char>());

		ret.from_json(nlohmann::json::parse(str), ret);
	}

	people_file.close();
	return ret;
}

void server::Database::set_usrinfo(std::string hash, pinfo_t usr){
	std::fstream file(std::string(dir + hash), std::fstream::in | std::fstream::out | std::fstream::binary | std::fstream::trunc);
	if(!file){
		std::cout << "Could not create file!" << std::endl;
		return;
	}

	nlohmann::json j;
	
	usr.to_json(j, usr);

	file << j.dump() << std::endl;
	
	file.close();
}