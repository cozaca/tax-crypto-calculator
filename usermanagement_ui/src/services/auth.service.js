import api from "./api";
import TokenService from "./token.service";

const register = (username, email, password) => {
  return api.post("/auth/signup", {
    username,
    email,
    password
  });
};

const login = (username, password) => {
  return api
    .post("/auth/signin", {
      username,
      password
    })
    .then((response) => {
        console.log("Response logine " + JSON.stringify(response.data))
      if (response.data.token) {
        console.log("set user " +  + JSON.stringify(response.data));
        TokenService.setUser(response.data);
      }

      return response.data;
    });
};

const logout = () => {
  TokenService.removeUser();
};

const getCurrentUser = () => {
  return JSON.parse(localStorage.getItem("user"));
};

const AuthService = {
  register,
  login,
  logout,
  getCurrentUser,
};

export default AuthService;