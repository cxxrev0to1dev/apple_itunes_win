// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include "cookies/cookie_constants.h"
#include "third_party/glog/logging.h"


namespace net {

namespace {
const char kPriorityLow[] = "low";
const char kPriorityMedium[] = "medium";
const char kPriorityHigh[] = "high";
}  // namespace

const std::string CookiePriorityToString(CookiePriority priority) {
  switch(priority) {
    case COOKIE_PRIORITY_HIGH:
      return kPriorityHigh;
    case COOKIE_PRIORITY_MEDIUM:
      return kPriorityMedium;
    case COOKIE_PRIORITY_LOW:
      return kPriorityLow;
    default:
      NOTREACHED();
  }
  return std::string();
}

CookiePriority StringToCookiePriority(const std::string& priority) {
  std::string priority_comp(priority);
  priority_comp = ToLower(priority_comp);

  if (priority_comp == kPriorityHigh)
    return COOKIE_PRIORITY_HIGH;
  if (priority_comp == kPriorityMedium)
    return COOKIE_PRIORITY_MEDIUM;
  if (priority_comp == kPriorityLow)
    return COOKIE_PRIORITY_LOW;

  return COOKIE_PRIORITY_DEFAULT;
}
std::string ToLower(const std::string& seque){
	if (!seque.size()){
		return "";
	}
	std::string var_seque = seque;
	std::transform(var_seque.begin(), var_seque.end(), var_seque.begin(), ::tolower);
	return var_seque;
}

}  // namespace net
