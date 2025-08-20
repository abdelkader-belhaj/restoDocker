<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Request;
use App\Service\FirebaseService;

final class DashboardController extends AbstractController
{
    private $firebaseService;

    public function __construct(FirebaseService $firebaseService)
    {
        $this->firebaseService = $firebaseService;
    }

    #[Route('/dashboard', name: 'app_dashboard')]
    public function index(Request $request): Response
    {
        $user = $request->getSession()->get('user');
        
        // Vérification du rôle admin
        if (!$user || $user['type'] !== 'admin') {
            return $this->redirectToRoute('app_login');
        }

        // Récupération des données depuis Firebase
        $orders = $this->firebaseService->getAllOrders();
        $tables = $this->firebaseService->getAllTables();
        $menus = $this->firebaseService->getAllMenus();

        // Normalisation des statuts des commandes
        foreach ($orders as &$order) {
            // Vérifier et définir un statut cohérent
            $status = isset($order['orderSummary']['status']) ? $order['orderSummary']['status'] : 
                     (isset($order['status']) ? $order['status'] : 'pending');
            
            // Mettre à jour les deux emplacements du statut
            $order['status'] = $status;
            if (!isset($order['orderSummary'])) {
                $order['orderSummary'] = [];
            }
            $order['orderSummary']['status'] = $status;
        }
        unset($order); // Nettoyer la référence

        // Normalisation des données des commandes
        $orders = array_map(function($order) {
            // S'assurer que les champs requis existent
            if (!isset($order['customerName']) && isset($order['customerInfo']['name'])) {
                $order['customerName'] = $order['customerInfo']['name'];
            }
            if (!isset($order['phone']) && isset($order['customerInfo']['phone'])) {
                $order['phone'] = $order['customerInfo']['phone'];
            }
            return $order;
        }, $orders);

        // Calcul des statistiques
        $totalOrders = count($orders);
        
        // Calcul du revenu total avec vérification de sécurité
        $totalRevenue = array_sum(array_map(function($order) {
            return isset($order['orderSummary']['totalAmount']) ? 
                floatval($order['orderSummary']['totalAmount']) : 
                (isset($order['total']) ? floatval($order['total']) : 0);
        }, $orders));
        
        // Traitement des tables et des réservations
        $tableStats = [
            'total' => count($tables),
            'available' => 0,
            'reserved' => 0,
            'occupied' => 0,
            'maintenance' => 0,
            'reservedDetails' => [] // Pour stocker les détails des tables réservées
        ];

        // Normaliser et compter les tables par statut
        $normalizedTables = [];
        foreach ($tables as $id => $table) {
            $status = isset($table['status']) ? strtolower($table['status']) : 'available';
            
            // Normaliser le statut
            if (!in_array($status, ['available', 'reserved', 'occupied', 'maintenance'])) {
                $status = 'available';
            }
            
            // Mettre à jour les statistiques
            $tableStats[$status]++;
            
            // Normaliser la table
            $reservation = null;
            $persons = 0;

            if ($status === 'reserved') {
                // Récupérer directement les données de réservation de la table
                $persons = intval($table['numberPeople'] ?? 0);
                $customerName = $table['name'] ?? 'Non spécifié';
                
                $reservation = [
                    'customerName' => $customerName,
                    'date' => $table['date'] ?? null,
                    'time' => $table['time'] ?? null,
                    'persons' => $persons
                ];
            }

            $normalizedTable = [
                'id' => $id,
                'number' => $table['number'] ?? substr($id, 0, 8),
                'capacity' => $table['capacity'] ?? null,
                'status' => $status,
                'persons' => $persons,
                'reservation' => $reservation
            ];

            // Ajouter les détails de réservation aux statistiques si la table est réservée
            if ($status === 'reserved' && isset($table['reservation'])) {
                $tableStats['reservedDetails'][] = [
                    'tableNumber' => $table['number'] ?? substr($id, 0, 8),
                    'customerName' => $table['reservation']['customerName'] ?? 'Non spécifié',
                    'persons' => $table['reservation']['persons'] ?? $table['capacity'] ?? 2
                ];
            }
            
            $normalizedTables[$id] = $normalizedTable;
        }
        
        // Mettre à jour la variable tables avec les données normalisées
        $tables = $normalizedTables;

        // Top 5 des plats les plus commandés
        $popularDishes = [];
        foreach ($orders as $order) {
            if (isset($order['items']) && is_array($order['items'])) {
                foreach ($order['items'] as $item) {
                    if (isset($item['id']) && !empty($item['id'])) {
                        $dishId = $item['id'];
                        if (!isset($popularDishes[$dishId])) {
                            $popularDishes[$dishId] = 0;
                        }
                        $popularDishes[$dishId]++;
                    }
                }
            }
        }
        arsort($popularDishes);
        $popularDishes = array_slice($popularDishes, 0, 5, true);

        // Données pour le graphique des ventes
        $salesData = [];
        $currentDate = date('Y-m-d');
        $thirtyDaysAgo = date('Y-m-d', strtotime('-30 days'));
        
        // Initialiser les 30 derniers jours avec des ventes à 0
        for ($date = $thirtyDaysAgo; $date <= $currentDate; $date = date('Y-m-d', strtotime($date . ' +1 day'))) {
            $salesData[$date] = 0;
        }

        // Ajouter les ventes réelles
        foreach ($orders as $order) {
            $orderDate = null;
            $orderTotal = 0;

            // Obtenir la date de la commande
            if (isset($order['orderDate'])) {
                $orderDate = date('Y-m-d', strtotime($order['orderDate']));
            } elseif (isset($order['timestamp']) && is_numeric($order['timestamp'])) {
                $orderDate = date('Y-m-d', $order['timestamp']);
            }

            // Obtenir le total de la commande
            if (isset($order['orderSummary']['totalAmount'])) {
                $orderTotal = floatval($order['orderSummary']['totalAmount']);
            } elseif (isset($order['total'])) {
                $orderTotal = floatval($order['total']);
            }

            // Ajouter au graphique si nous avons une date valide
            if ($orderDate && isset($salesData[$orderDate])) {
                $salesData[$orderDate] += $orderTotal;
            }
        }
        ksort($salesData);

        return $this->render('dashboard/index.html.twig', [
            'controller_name' => 'DashboardController',
            'user' => $user,
            'stats' => [
                'totalOrders' => $totalOrders,
                'totalRevenue' => $totalRevenue,
                'tables' => $tableStats,
                'pendingReservations' => $tableStats['reserved'],
            ],
            'recentOrders' => array_slice($orders, -5, 5, true),
            'popularDishes' => $popularDishes,
            'salesData' => $salesData,
            'tables' => $tables,
            'menu' => $menus
        ]);
    }
}