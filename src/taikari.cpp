#include "taikari.h"

int64_t sendHttpRequest(online_manager_t cls, send_request_t func,
                        const char *url, request_type_t request_type,
                        const char *header, const char *post_body)
{
  // check pointers
  if (!cls)
    return -100;
  if (!func)
    return -101;
  if (!url)
    return -102;
  if (!header)
    return -103;
  if (!post_body)
    return -104;

  // create objects
  auto _url = std::string(url);
  auto _tag_name = std::string("");
  auto _post_body = std::string(post_body);
  auto _extra_header = split(header, "\n");
  auto _callback = std::function<void(void *, void *)>(responseCallback);

  // call send request
  return func(cls, _url, request_type, _tag_name, _callback, _extra_header, _post_body, 0);
}

void responseCallback(void *client, void *response)
{
  // do nothing
}

std::vector<std::string> split(std::string s, std::string delimiter)
{
  size_t pos_start = 0, pos_end, delim_len = delimiter.length();
  std::string token;
  std::vector<std::string> res;

  while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
  {
    token = s.substr(pos_start, pos_end - pos_start);
    pos_start = pos_end + delim_len;
    res.push_back(token);
  }

  res.push_back(s.substr(pos_start));
  return res;
}
