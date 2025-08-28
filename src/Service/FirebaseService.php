<?php

namespace App\Service;

use Kreait\Firebase\Factory;
use Kreait\Firebase\Database;

class FirebaseService
{
    private Database $database;
    private $auth;

    public function __construct(string $credentialsPath, string $databaseUrl)
    {
        $factory = (new Factory)
            ->withServiceAccount($credentialsPath)
            ->withDatabaseUri($databaseUrl);

        $this->database = $factory->createDatabase();
        $this->auth = $factory->createAuth();
    }

    public function getDatabase(): Database
    {
        return $this->database;
    }

    // --------------------------
    // 🎯 MENUS
    // --------------------------
    public function createMenu(array $data): void
    {
        $this->database->getReference('menus')->push($data);
    }

    public function getAllMenus(): array
    {
        return $this->database->getReference('menus')->getValue() ?? [];
    }

    public function getMenu(string $key): ?array
    {
        return $this->database->getReference("menus/{$key}")->getValue();
    }

    public function updateMenu(string $key, array $data): void
    {
        $this->database->getReference("menus/{$key}")->update($data);
    }

    public function deleteMenu(string $key): void
    {
        $this->database->getReference("menus/{$key}")->remove();
    }

    // --------------------------
    // 🆕 SPECIALS
    // --------------------------
    public function createSpecial(array $data): void
    {
        $this->database->getReference('specials')->push($data);
    }

    public function getAllSpecials(): array
    {
        return $this->database->getReference('specials')->getValue() ?? [];
    }

    public function getSpecial(string $key): ?array
    {
        return $this->database->getReference("specials/{$key}")->getValue();
    }

    public function updateSpecial(string $key, array $data): void
    {
        $this->database->getReference("specials/{$key}")->update($data);
    }

    public function deleteSpecial(string $key): void
    {
        $this->database->getReference("specials/{$key}")->remove();
    }

    // --------------------------
    // 🍽️ TABLES
    // --------------------------
    public function createTable(array $data): void
    {
        $this->database->getReference('tables')->push($data);
    }

    public function getAllTables(): array
    {
        return $this->database->getReference('tables')->getValue() ?? [];
    }

    public function getTable(string $key): ?array
    {
        return $this->database->getReference("tables/{$key}")->getValue();
    }

    public function updateTable(string $key, array $data): void
    {
        $this->database->getReference("tables/{$key}")->update($data);
    }

    public function deleteTable(string $key): void
    {
        $this->database->getReference("tables/{$key}")->remove();
    }

    // --------------------------
    // 👨‍🍳 CHEFS
    // --------------------------
    public function createChef(array $data): void
    {
        $this->database->getReference('chefs')->push($data);
    }

    public function getAllChefs(): array
    {
        return $this->database->getReference('chefs')->getValue() ?? [];
    }

    public function getChef(string $key): ?array
    {
        return $this->database->getReference("chefs/{$key}")->getValue();
    }

    public function updateChef(string $key, array $data): void
    {
        $this->database->getReference("chefs/{$key}")->update($data);
    }

    public function deleteChef(string $key): void
    {
        $this->database->getReference("chefs/{$key}")->remove();
    }

    // --------------------------
    // 📩 CONTACTS
    // --------------------------
    public function createContact(array $data): void
    {
        $this->database->getReference('contacts')->push($data);
    }

    public function getAllContacts(): array
    {
        return $this->database->getReference('contacts')->getValue() ?? [];
    }

    public function getContact(string $key): ?array
    {
        return $this->database->getReference("contacts/{$key}")->getValue();
    }

    public function updateContact(string $key, array $data): void
    {
        $this->database->getReference("contacts/{$key}")->update($data);
    }

    public function deleteContact(string $key): void
    {
        $this->database->getReference("contacts/{$key}")->remove();
    }

    // --------------------------
    // 🖼️ GALLERY
    // --------------------------
    public function createGallery(array $data): void
    {
        $this->database->getReference('galleries')->push($data);
    }

    public function getAllGalleries(): array
    {
        return $this->database->getReference('galleries')->getValue() ?? [];
    }

    public function getGallery(string $key): ?array
    {
        return $this->database->getReference("galleries/{$key}")->getValue();
    }

    public function updateGallery(string $key, array $data): void
    {
        $this->database->getReference("galleries/{$key}")->update($data);
    }

    public function deleteGallery(string $key): void
    {
        $this->database->getReference("galleries/{$key}")->remove();
    }

    // --------------------------
    // 🎉 PARTTIES
    // --------------------------
    public function createParttie(array $data): void
    {
        $this->database->getReference('partties')->push($data);
    }

    public function getAllPartties(): array
    {
        return $this->database->getReference('partties')->getValue() ?? [];
    }

    public function getParttie(string $key): ?array
    {
        return $this->database->getReference("partties/{$key}")->getValue();
    }

    public function updateParttie(string $key, array $data): void
    {
        $this->database->getReference("partties/{$key}")->update($data);
    }

    public function deleteParttie(string $key): void
    {
        $this->database->getReference("partties/{$key}")->remove();
    }

    // --------------------------
    // 🛒 ORDERS
    // --------------------------
    public function createOrder(array $data): void
    {
        $this->database->getReference('orders')->push($data);
    }

    public function getAllOrders(): array
    {
        return $this->database->getReference('orders')->getValue() ?? [];
    }

    public function getOrder(string $key): ?array
    {
        return $this->database->getReference("orders/{$key}")->getValue();
    }

    public function updateOrder(string $key, array $data): void
    {
        $this->database->getReference("orders/{$key}")->update($data);
    }

    public function deleteOrder(string $key): void
    {
        $this->database->getReference("orders/{$key}")->remove();
    }

    // --------------------------
    // 👤 USERS
    // --------------------------
    public function createUser(array $data): void
    {
        $this->database->getReference('users')->push($data);
    }

    public function getAllUsers(): array
    {
        return $this->database->getReference('users')->getValue() ?? [];
    }

    public function getUser(string $key): ?array
    {
        return $this->database->getReference("users/{$key}")->getValue();
    }

    public function updateUser(string $key, array $data): void
    {
        $this->database->getReference("users/{$key}")->update($data);
    }

    public function deleteUser(string $key): void
    {
        $this->database->getReference("users/{$key}")->remove();
    }

    public function getUserByEmail(string $email): ?array
    {
        $users = $this->getAllUsers();
        foreach ($users as $key => $user) {
            if ($user['email'] === $email) {
                return ['key' => $key] + $user;
            }
        }
        return null;
    }

    public function getAllAdmins(): array
    {
        $users = $this->getAllUsers();
        return array_filter($users, function($user) {
            return isset($user['type']) && $user['type'] === 'admin';
        });
    }

    public function getAllClients(): array
    {
        $users = $this->getAllUsers();
        return array_filter($users, function($user) {
            return !isset($user['type']) || $user['type'] === 'client';
        });
    }

    public function verifyToken(string $token): array
    {
        try {
            $verifiedToken = $this->auth->verifyIdToken($token);
            return [
                'email' => $verifiedToken['email'] ?? null,
                'uid' => $verifiedToken['sub'] ?? $verifiedToken['user_id'] ?? null,
                'verified' => true
            ];
        } catch (\Exception $e) {
            throw new \Exception('Token invalide : ' . $e->getMessage());
        }
    }
}
