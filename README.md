# build an api rails demo

[使用 Rails 构建 API 实践](https://ruby-china.org/topics/25822)

This README would normally document whatever steps are necessary to get the
application up and running.

Things you may want to cover:

* Ruby version
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-linux]

* System dependencies (third party gems)
  * to build a simple, robust and scaleable authorization system
    [pundit](https://github.com/elabs/pundit)
  * paginate
    [kaminari]()
  * Rate limit
    [redis-throttle](https://github.com/andreareginato/redis-throttle.git)

* Configuration

* Database creation

* Database initialization

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions

* ...


Please feel free to use a different markup language if you do not plan to run
<tt>rake doc:app</tt>.


# Midi's steps

加入第一个 API resource

BaseController
$ bundle exe rails g controller api/v1/base --no-assets

class Api::V1::BaseController < ApplicationController
  # disable the CSRF token
  protect_from_forgery with: :null_session

  # disable cookies (no set-cookies header in response)
  before_action :destroy_session

  # disable the CSRF token
  skip_before_action :verify_authenticity_token

  def destroy_session
    request.session_options[:skip] = true
  end
end


配置路由:

config/routes.rb,

namespace :api do
  namespace :v1 do
    resources :users, only: [:index, :create, :show, :update, :destroy]
    # 原文有 microposts, 我们现在把它注释掉
    # resources :microposts, only: [:index, :create, :show, :update, :destroy]
  end
end

生成控制器 Api::V1::UsersController
$ bundle exe rails g controller api/v1/users --no-assets
class Api::V1::UsersController < Api::V1::BaseController
  def show
    @user = User.find(params[:id])
  end
end

app/views/api/v1/users/show.json.jbuilder

json.user do
  json.(@user, :id, :email, :name, :activated, :admin, :created_at, :updated_at)
end

User 模型和 users 表
rails g model User  email name activated:datetime admin:boolean

t.boolean :admin, default: false

数据迁移:

$ bundle exe rake db:migrate

种子数据:

db/seeds.rb,

users = User.create([
  {
    email: 'test-user-00@mail.com',
    name: 'test-user-00',
    activated: DateTime.now,
    admin: false
  },
  {
    email: 'test-user-01@mail.com',
    name: 'test-user-01',
    activated: DateTime.now,
    admin: false
  }
  ])



$ rake routes
      Prefix Verb   URI Pattern                 Controller#Action
api_v1_users GET    /api/v1/users(.:format)     api/v1/users#index
             POST   /api/v1/users(.:format)     api/v1/users#create
 api_v1_user GET    /api/v1/users/:id(.:format) api/v1/users#show
             PATCH  /api/v1/users/:id(.:format) api/v1/users#update
             PUT    /api/v1/users/:id(.:format) api/v1/users#update
             DELETE /api/v1/users/:id(.:format) api/v1/users#destroy


curl -i http://localhost:8080/api/v1/users/1.json

```
curl -i http://localhost:8080/api/v1/users/1.json
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: application/json; charset=utf-8
Etag: W/"26a73698c493062550be9967b03e9dfc"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: c316110a-bee8-4224-9b24-497cfb29e2ea
X-Runtime: 0.902682
Server: WEBrick/1.3.1 (Ruby/2.3.0/2015-12-25)
Date: Wed, 24 Aug 2016 08:33:53 GMT
Content-Length: 204
Connection: Keep-Alive
{"user":{"id":1,"email":"test-user-00@mail.com","name":"test-user-00","activated":"2016-08-24T08:19:49.546Z","admin":false,"created_at":"2016-08-24T08:19:49.566Z","updated_at":"2016-08-24T08:19:49.566Z"}}
```


rails g migration add_authentication_token_to_users

class User < ActiveRecord::Base
  before_create :generate_authentication_token

  def generate_authentication_token
    loop do
      self.authentication_token  = SecureRandom.base64(64)
      break if !User.find_by(authentication_token: authentication_token)
    end
  end

  def reset_auth_token!
    generate_authentication_token
    save
  end
end

rails g controller api/v1/sessions --no-assets



rails g migration add_password_digest_to_users

给数据库中已存在的测试用户增加密码和 authentication token

这个任务可以在 rails console 下完成,

首先启动 rails console,

$ bundle exe rails c
然后在 rails console 里执行,

User.all.each {|user|
  user.password = '123123'
  user.reset_auth_token!
}


curl -i -X POST -d "user[email]=test-user-00@mail.com&user[password]=123123" http://localhost:8080/api/v1/sessions.json
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: application/json; charset=utf-8
Etag: W/"db83ee8e656e00f6a17dcbba3e6e6114"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: ceed1cad-0d5a-4f0c-b49a-5dadab1c7bad
X-Runtime: 0.924739
Server: WEBrick/1.3.1 (Ruby/2.3.0/2015-12-25)
Date: Wed, 24 Aug 2016 09:05:44 GMT
Content-Length: 155
Connection: Keep-Alive

{"session":{"id":1,"name":"test-user-00","admin":false,"token":"WK0fsNBA2mj/ZmHxMuCkM52qnLTpFOsAAFSGOlXvskETuu0al+atQAUSuYDSY1Mpsvc3mQE1QoGbWesf1MvmtA=="}}

curl -i -X POST -d "user[email]=test-user-00@mail.com&user[password]=1" http://localhost:8080/api/v1/sessions.json

HTTP/1.1 401 Unauthorized
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: text/plain; charset=utf-8
Cache-Control: no-cache
X-Request-Id: 8b501e02-8845-4a02-93ed-4b6ff005f874
X-Runtime: 0.083789
Server: WEBrick/1.3.1 (Ruby/2.3.0/2015-12-25)
Date: Wed, 24 Aug 2016 09:12:51 GMT
Content-Length: 0
Connection: Keep-Alive



## Authenticate User

首先在 Api::V1::BaseController 里实现 authenticate_user! 方法:

app/controllers/api/v1/base_controller.rb,

class Api::V1::BaseController < ApplicationController

+  def authenticate_user!
+    token, options = ActionController::HttpAuthentication::Token.token_and_options(request)

+    user_email = options.blank?? nil : options[:email]
+    user = user_email && User.find_by(email: user_email)

+    if user && ActiveSupport::SecurityUtils.secure_compare(user.authentication_token, token)
+      self.current_user = user
+    else
+      return unauthenticated!
+    end
+  end

end

我们构造一个测试用例, 这个测试用例包括以下一些步骤:

用户登录成功, 服务端返回其 email, token 等数据
用户请求 API 更新其 name, 用户发送的 token 合法, 更新成功
用户请求 API 更新其 name, 用户发送的 token 非法, 更新失败


curl -i -X POST -d "user[email]=test-user-00@mail.com&user[password]=123123" https://rails5-midikang.c9users.io:8080/api/v1/sessions.json
HTTP/1.1 200 OK
x-xss-protection: 1; mode=block
x-content-type-options: nosniff
content-type: application/json; charset=utf-8
etag: W/"db83ee8e656e00f6a17dcbba3e6e6114"
cache-control: max-age=0, private, must-revalidate
x-request-id: febe45dc-68d4-480b-9463-aea16b05fd86
x-runtime: 0.083588
server: WEBrick/1.3.1 (Ruby/2.3.0/2015-12-25)
date: Thu, 25 Aug 2016 03:52:05 GMT
content-length: 155
X-BACKEND: apps-proxy

{"session":{"id":1,"name":"test-user-00","admin":false,"token":"WK0fsNBA2mj/ZmHxMuCkM52qnLTpFOsAAFSGOlXvskETuu0al+atQAUSuYDSY1Mpsvc3mQE1QoGbWesf1MvmtA=="}}



=================
$ curl -i -X PUT -d "user[name]=midikang-user" \
>   --header "Authorization: Token token=WK0fsNBA2mj/ZmHxMuCkM52qnLTpFOsAAFSGOlXvskETuu0al+atQAUSuYDSY1Mpsvc3mQE1QoGbWesf1MvmtA==, \
>   email=test-user-00@mail.com" \
>   http://localhost:8080//api/v1/users/1
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Type: application/json; charset=utf-8
Etag: W/"b5c690436ed9dea6657b402a7fc8a009"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: e1b9c448-660c-46c1-b3f9-723c033e714b
X-Runtime: 0.081411
Server: WEBrick/1.3.1 (Ruby/2.3.0/2015-12-25)
Date: Thu, 25 Aug 2016 03:54:42 GMT
Content-Length: 40
Connection: Keep-Alive

{"user":{"id":1,"name":"midikang-user"}}


## 增加授权(Authorization)

上面的测试有个问题，就是当前登录的用户可以把其他用户的 name 更新，这个应该是不被允许的，所以我们
还需要增加一个权限认证的机制。在这里我们使用 Pundit 来
实现权限认证。

安装 pundit

Gemfile,

+ gem 'pundit'
$ bundle install
app/controllers/api/v1/base_controller.rb,

class Api::V1::BaseController < ApplicationController
  + include Pundit
end

rails g pundit:install
Running via Spring preloader in process 31036
      create  app/policies/application_policy.rb

将 policies 目录放到 rails 的自动加载路径中:

config/application.rb,

module BuildAnApiRailsDemo
  class Application < Rails::Application
+    config.autoload_paths << Rails.root.join('app/policies')
  end
end


# 分页
建立 Micropost 模型

$ bundle exe rails g model Micropost


namespace :data do
  task :create_microposts => [:environment] do
    user = User.find(1)
    100.times do |i|
      Micropost.create(user_id: user.id, title: "This is the title-#{i}", content: "This is the content-#{i}")
    end
  end
end

```
rake data:create_microposts
```

## Api::V1::MicropostsController
```
rails g controller api/v1/microposts --no-assets
```



```
$ rake routes
           Prefix Verb   URI Pattern                                Controller#Action
     api_v1_users GET    /api/v1/users(.:format)                    api/v1/users#index
                  POST   /api/v1/users(.:format)                    api/v1/users#create
      api_v1_user GET    /api/v1/users/:id(.:format)                api/v1/users#show
                  PATCH  /api/v1/users/:id(.:format)                api/v1/users#update
                  PUT    /api/v1/users/:id(.:format)                api/v1/users#update
                  DELETE /api/v1/users/:id(.:format)                api/v1/users#destroy
  api_v1_sessions POST   /api/v1/sessions(.:format)                 api/v1/sessions#create
api_v1_microposts GET    /api/v1/user/:user_id/microposts(.:format) api/v1/microposts#index
```



API 调用频率限制(Rate Limit)

我们使用 redis-throttle 来实现这个功能。

Gemfile,

gem 'redis-throttle', git: 'git://github.com/andreareginato/redis-throttle.git'
