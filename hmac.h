#pragma once
#include <string>
#include "sha1.hpp"
namespace hmac {

   std::string get_hash_sha1(const std::string& input) {
      SHA1 sha1;
      sha1.update(input);
      return sha1.final(false);
   }

   std::string get_hmac(std::string key, const std::string msg) {
      size_t block_size = 512/8;//sha1 block size is 512bit
      if (key.size() < block_size) {

         key.resize(block_size, '\0');//Fit to block size
      }
      std::string ikeypad;
      std::string okeypad;
      ikeypad.reserve(block_size);
      okeypad.reserve(block_size);
      for (size_t i = 0; i < block_size; ++i) {
         ikeypad.push_back('\x36' ^ key[i]);
         okeypad.push_back('\x5c' ^ key[i]);
      }

      return get_hash_sha1(okeypad + get_hash_sha1(ikeypad + msg));
   }
}