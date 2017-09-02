/*
Copyright Bubi Technologies Co., Ltd. 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "general.h"

namespace bubi {
	std::string GetDataSecuretKey() {
		//key must be string, ended with 0, length must be 32 + 1.
		/*char key[] = { 'H', 'C', 'P', 'w', 'z', '!', 'H', '1', 'Y', '3', 'j', 'a', 'J', '*', '|', 'q', 'w', '8', 'K', '<', 'e', 'o', '7', '>', 'Q', 'i', 'h', ')', 'r', 'P', 'q', '1', 0 };*/
		char key[] = { 'Z', 'C', 'O', 'w', 'z', '!', 'F', '1', 'Y', '3', 'j', 'b', 'S', '*', '|', 'q', 'w', '8', 'K', 'a', 'e', 'o', '7', '>', 'Q', 'q', 'h', ')', 'r', '!', 'q', '1', 8 };
		
		return key;
	}
}
