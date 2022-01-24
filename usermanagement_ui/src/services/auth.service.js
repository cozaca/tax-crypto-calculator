import axios from "axios";

const API_URL = "http://localhost:8080/api/auth/";

const register = (username, email, password) => {
    return axios.post(API_URL + "signup", {
        username,
        email,
        password
    });
};

const login = (username, password) => {
    return axios.post(API_URL + "signin", {
        username,
        password
    })
    .then((response) => {
        console.log("Login response " + JSON.stringify(response.data));
        if(response.data.accessToken) {
            localStorage.setItem("user", JSON.stringify(response.data));
            console.log("### get item from local storage " + localStorage.getItem("user"));
        }

        return response.data;
    })
}

const logout = () => {
    localStorage.removeItem("user");
};

const getCurrentUser = () => {
    return JSON.parse(localStorage.getItem("user"));
}

export default {
    register,
    login,
    logout,
    getCurrentUser
};