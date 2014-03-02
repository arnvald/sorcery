require 'spec_helper'

describe "the login process", :type => :feature do
  before(:all) do
    sorcery_reload!
    create_new_user
  end

  it "handles unverified request" do
    visit root_path
    page.find("input[name='authenticity_token']").set("incorrect_token")
    fill_in 'Email', with: 'bla@bla.com'
    fill_in 'Password', with: 'secret'
    click_button 'Login'

    expect(page).to have_content "error, not logged in"
  end

  it "logs user correctly" do
    visit root_path
    fill_in 'Email', with: 'bla@bla.com'
    fill_in 'Password', with: 'secret'
    click_button 'Login'

    expect(page).to have_content "logged in correctly"
  end
end