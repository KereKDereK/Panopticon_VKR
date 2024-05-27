#include <iostream>
#include <unistd.h>

int ***REMOVED***_initiated() {
	std::cout << "***REMOVED***" << std::endl;
	sleep(3);
	return 1;
}


int main() {
	int times = 5;
	for(int i = 0; i < times; ++i){
		***REMOVED***_initiated();
	}
	return times;
}
