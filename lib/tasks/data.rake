namespace :data do
  task :create_microposts => [:environment] do
    user = User.find(1)
    100.times do |i|
      Micropost.create(user_id: user.id, title: "This is the title-#{i}", content: "This is the content-#{i}")
    end
  end
end