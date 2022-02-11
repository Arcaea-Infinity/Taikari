#ifndef _TAIKRI_H_
#define _TAIKRI_H_

#include <string>
#include <vector>
#include <functional>

// request type
typedef enum request_type
{
  get = 0,
  post = 1
} request_type_t;

// online manager lpthis
typedef void *online_manager_t;

typedef int64_t (*send_request_t)(online_manager_t cls,
                                  std::string url,
                                  std::int32_t request_type,
                                  std::string tag_name,
                                  std::function<void(void *, void *)> const &callback,
                                  std::vector<std::string> extra_header,
                                  std::string post_body,
                                  bool zero);

typedef size_t (*set_favorite_character_t)(online_manager_t cls,
                                           std::size_t id,
                                           std::function<void(void *, void *)> const &callback);

/**
 * @brief Call online manager
 * 
 * @param cls 
 * @param func 
 * @param url 
 * @param request_type 
 * @param header 
 * @param post_body 
 * @return int64_t 
 */
int64_t sendHttpRequest(online_manager_t cls, send_request_t func,
                        const char *url, request_type_t request_type,
                        const char *header, const char *post_body) asm("sendHttpRequest");

/**
 * @brief Call set favorite character
 * @param cls
 * @param func
 * @param id
 * @return
 */
size_t setFavoriteCharacter(online_manager_t cls, set_favorite_character_t func,
                            size_t id) asm("setFavoriteCharacter");

/**
 * @brief Result callback
 * 
 * @param client 
 * @param response 
 */
void responseCallback(void *client, void *response);

/**
 * @brief split string
 * https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
 * 
 * @param s 
 * @param delimiter 
 * @return std::vector<std::string> 
 */
std::vector<std::string> split(std::string s, std::string delimiter);

#endif /* _TAIKRI_H_ */
