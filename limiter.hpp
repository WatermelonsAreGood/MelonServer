#include <chrono>

namespace limiter {
	class Bucket {
		uint16_t rate;
		uint16_t per;
		float allowance;
		std::chrono::time_point<std::chrono::_V2::steady_clock, std::chrono::duration<long int, std::ratio<1l, 1000000000l>>> last_check;
	public:
		Bucket(uint16_t a, uint16_t b) : rate(a), per(b), allowance(a){};
		bool can_spend(uint16_t = 1);
	};
	
	class Simple {
		float rate;
		std::chrono::time_point<std::chrono::_V2::steady_clock, std::chrono::duration<long int, std::ratio<1l, 1000000000l>>> last_check;
	public:
		Simple(float a) : rate(a){};
		bool can_spend();
	};
}

class ClientLimit {
public:
	limiter::Simple name;
	limiter::Simple room;
	limiter::Simple rmls;
	ClientLimit() : name(2), room(1.6f), rmls(.8f){};
};

class RoomLimit {
public:
	limiter::Simple curs;
	limiter::Bucket chat;
	limiter::Simple noterate;
	RoomLimit() : curs(0.045f), chat(4, 5), noterate(0.05f){};
};
