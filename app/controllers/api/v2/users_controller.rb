class Api::V2::UsersController < ApplicationController
  def show
    @user = User.find(params[:id])
  end
end
