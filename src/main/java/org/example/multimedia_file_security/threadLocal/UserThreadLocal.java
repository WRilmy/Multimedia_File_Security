package org.example.multimedia_file_security.threadLocal;

public class UserThreadLocal {
    public static ThreadLocal<Long> userThreadLocal = new ThreadLocal<>();

    public static void setCurrentId(Long id) {
        userThreadLocal.set(id);
    }

    public static Long getCurrentId() {
        return userThreadLocal.get();
    }

    public static void removeCurrentId() {
        userThreadLocal.remove();
    }

}
