import { AuthProvider } from 'ra-core';
import axios from 'axios';
import decodeJwt from 'jwt-decode';
//import { AUTH_LOGIN, AUTH_LOGOUT, AUTH_ERROR, AUTH_CHECK, AUTH_GET_PERMISSIONS } from 'react-admin';

interface Identity {
    role: string;
}

interface MyToken {
    identity: Identity;
}

const authProvider: AuthProvider = {
    login: ({ username, password }) => {
        // localStorage.setItem('username', username);
        // // accept all username/password combinations
        // return Promise.resolve();
        //const { username, password } = params;
        let data = JSON.stringify({ username, password });

        return axios
            .post('http://localhost:5000/api/login/', data, {
                headers: {
                    'Content-Type': 'application/json',
                },
            })
            .then(res => {
                if (res.data.error || res.status !== 200) {
                    throw new Error(res.data.error);
                } else {
                    const token = res.data.token;
                    const decodedToken = decodeJwt<MyToken>(token);
                    const role = decodedToken.identity.role;
                    localStorage.setItem('token', token);
                    localStorage.setItem('role', role);
                    return Promise.resolve();
                }
            });
    },
    logout: () => {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
        return Promise.resolve();
    },
    checkError: params => {
        const { status } = params;
        if (status === 401 || status === 403) {
            localStorage.removeItem('token');
            localStorage.removeItem('role');
            return Promise.reject();
        }
        return Promise.resolve();
    },
    checkAuth: () =>
        //localStorage.getItem('username') ? Promise.resolve() : Promise.reject(),
        localStorage.getItem('token')
            ? Promise.resolve()
            : Promise.reject({ redirectTo: '/login' }),
    getPermissions: () => {
        const role = localStorage.getItem('role');
        return role ? Promise.resolve(role) : Promise.reject();
    },
};

export default authProvider;
