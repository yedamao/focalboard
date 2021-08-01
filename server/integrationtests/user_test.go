package integrationtests

import (
	"testing"

	"github.com/mattermost/focalboard/server/api"
	"github.com/mattermost/focalboard/server/utils"
	"github.com/stretchr/testify/require"
)

func TestUserRegister(t *testing.T) {
	th := SetupTestHelperWithoutToken().InitBasic()
	defer th.TearDown()

	// register
	registerRequest := &api.RegisterRequest{
		Username: "damao",
		Email:    "mock@test.com",
		Password: utils.CreateGUID(),
	}
	success, resp := th.Client.Register(registerRequest)
	require.NoError(t, resp.Error)
	require.True(t, success)

	// register again will failed
	success, resp = th.Client.Register(registerRequest)
	require.Error(t, resp.Error)
	require.False(t, success)
}

func TestUserLogin(t *testing.T) {
	th := SetupTestHelperWithoutToken().InitBasic()
	defer th.TearDown()

	t.Run("with nonexist user", func(t *testing.T) {
		loginRequest := &api.LoginRequest{
			Type:     "normal",
			Username: "nonexistuser",
			Email:    "",
			Password: utils.CreateGUID(),
		}
		data, resp := th.Client.Login(loginRequest)
		require.Error(t, resp.Error)
		require.Nil(t, data)
	})

	t.Run("with registered user", func(t *testing.T) {
		// register
		username := "damao"
		email := "mock@test.com"
		password := utils.CreateGUID()
		register(t, th, username, email, password)

		// login
		login(t, th, username, "", password)
	})
}

func TestGetUserMe(t *testing.T) {
	th := SetupTestHelperWithoutToken().InitBasic()
	defer th.TearDown()

	t.Run("not login yet", func(t *testing.T) {
		me, resp := th.Client.GetUserMe()
		require.Error(t, resp.Error)
		require.Nil(t, me)
	})

	t.Run("logged in", func(t *testing.T) {
		// register && login
		username := "damao"
		email := "mock@test.com"
		password := utils.CreateGUID()
		register(t, th, username, email, password)
		login(t, th, username, "", password)

		// get user me
		me, resp := th.Client.GetUserMe()
		require.NoError(t, resp.Error)
		require.NotNil(t, me)
	})
}

func TestGetUser(t *testing.T) {
	th := SetupTestHelperWithoutToken().InitBasic()
	defer th.TearDown()

	// register && login
	username := "damao"
	email := "mock@test.com"
	password := utils.CreateGUID()
	register(t, th, username, email, password)
	login(t, th, username, "", password)

	me, resp := th.Client.GetUserMe()
	require.NoError(t, resp.Error)
	require.NotNil(t, me)

	t.Run("me's id", func(t *testing.T) {
		user, resp := th.Client.GetUser(me.ID)
		require.NoError(t, resp.Error)
		require.NotNil(t, user)
		require.Equal(t, me.ID, user.ID)
		require.Equal(t, me.Username, user.Username)
	})

	t.Run("nonexist user", func(t *testing.T) {
		user, resp := th.Client.GetUser("nonexistid")
		require.Error(t, resp.Error)
		require.Nil(t, user)
	})
}

func TestUserChangePassword(t *testing.T) {
	th := SetupTestHelperWithoutToken().InitBasic()
	defer th.TearDown()

	// register && login
	username := "damao"
	email := "mock@test.com"
	password := utils.CreateGUID()
	register(t, th, username, email, password)
	login(t, th, username, "", password)

	originalMe, resp := th.Client.GetUserMe()
	require.NoError(t, resp.Error)
	require.NotNil(t, originalMe)

	// change password
	success, resp := th.Client.UserChangePassword(originalMe.ID, &api.ChangePasswordRequest{
		OldPassword: password,
		NewPassword: utils.CreateGUID(),
	})
	require.NoError(t, resp.Error)
	require.True(t, success)
}

func register(t *testing.T, th *TestHelper, username, email, password string) {
	registerRequest := &api.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
	success, resp := th.Client.Register(registerRequest)
	require.NoError(t, resp.Error)
	require.True(t, success)
}

func login(t *testing.T, th *TestHelper, username, email, password string) {
	loginRequest := &api.LoginRequest{
		Type:     "normal",
		Username: username,
		Email:    email,
		Password: password,
	}
	data, resp := th.Client.Login(loginRequest)
	require.NoError(t, resp.Error)
	require.NotNil(t, data)
	require.NotNil(t, data.Token)
}
