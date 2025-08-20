<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

final class OrderController extends AbstractController
{
    #[Route('/menuC', name: 'app_menu_commande')]
    public function index(FirebaseService $firebaseService): Response
    {
        $database = $firebaseService->getDatabase();
        $snapshot = $database->getReference('menus')->getSnapshot();
        $menus = $snapshot->getValue();

        $menusByType = [];
        $featuredItems = [];

        if ($menus) {
            foreach ($menus as $key => $menu) {
                if (isset($menu['type'])) {
                    $type = strtolower($menu['type']);
                    $menuWithSlug = array_merge($menu, [
                        'slug' => $key,
                        'image' => $menu['image'] ?? null
                    ]);
                    $menusByType[$type][] = $menuWithSlug;
                    
                    // Ajoutez les 3 premiers menus comme featured
                    if (count($featuredItems) < 3) {
                        $featuredItems[] = $menuWithSlug;
                    }
                }
            }
        }

        return $this->render('order/indexFront.html.twig', [
            'menusByType' => $menusByType,
            'featuredItems' => $featuredItems
        ]);
    }
    #[Route('/admin/orders', name: 'admin_orders')]
    public function adminOrders(FirebaseService $firebaseService): Response
    {
        $database = $firebaseService->getDatabase();
        $snapshot = $database->getReference('orders')->getSnapshot();
        $orders = $snapshot->getValue() ?? [];

        // On veut les commandes les plus récentes en haut
        $orders = array_reverse($orders, true);

        return $this->render('order/admin_orders.html.twig', [
            'orders' => $orders
        ]);
    }

    #[Route('/api/orders', name: 'api_create_order', methods: ['POST'])]
    public function createOrder(Request $request, FirebaseService $firebaseService): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        
        if (!$data) {
            return new JsonResponse(['error' => 'Invalid data'], 400);
        }

        // Debug: Afficher les données reçues
        error_log('Données reçues : ' . print_r($data, true));

        // Formater et enrichir les données de la commande
        $formattedData = [
            'items' => array_map(function($item) {
                return [
                    'id' => $item['id'] ?? '', // Ajout de l'id du plat
                    'title' => $item['title'] ?? '',
                    'quantity' => $item['quantity'] ?? 0,
                    'unitPrice' => $item['unitPrice'] ?? 0,
                    'totalPrice' => $item['totalPrice'] ?? 0,
                    'category' => $item['category'] ?? '',
                    'image' => $item['image'] ?? '',
                    'customizations' => $item['customizations'] ?? []
                ];
            }, $data['items'] ?? []),
            'orderSummary' => [
                'totalQuantity' => $data['orderSummary']['totalQuantity'] ?? 0,
                'subtotal' => $data['orderSummary']['subtotal'] ?? 0,
                'deliveryFee' => $data['orderSummary']['deliveryFee'] ?? 0,
                'totalAmount' => $data['orderSummary']['totalAmount'] ?? 0,
                'status' => 'pending'
            ],
            'orderType' => $data['orderType'] ?? 'Sur place',
            'status' => 'pending',
            'orderDate' => (new \DateTime())->format('Y-m-d H:i:s'),
            'customerInfo' => [
                'name' => $data['customerInfo']['name'] ?? '',
                'phone' => $data['customerInfo']['phone'] ?? '',
                'address' => $data['customerInfo']['address'] ?? '',
                'tableNumber' => $data['customerInfo']['tableNumber'] ?? ''
            ]
        ];

        try {
            // Debug: Afficher les données formatées
            error_log('Données formatées : ' . print_r($formattedData, true));
            
            // Utiliser le FirebaseService pour créer la commande
            $firebaseService->createOrder($formattedData);
            
            return new JsonResponse([
                'success' => true,
                'message' => 'Order created successfully',
                'data' => $formattedData
            ], 201);
        } catch (\Exception $e) {
            return new JsonResponse([
                'error' => 'Failed to create order',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    #[Route('/admin/orders/{orderId}/status', name: 'admin_update_order_status', methods: ['POST'])]
    public function updateOrderStatus(string $orderId, Request $request, FirebaseService $firebaseService): Response
    {
        $newStatus = $request->request->get('status');
        if (!$newStatus) {
            return $this->redirectToRoute('app_dashboard');
        }

        try {
            $database = $firebaseService->getDatabase();
            $orderRef = $database->getReference('orders/' . $orderId);
            $order = $orderRef->getValue();
            
            if ($order) {
                // Mettre à jour le statut dans la commande
                $order['status'] = $newStatus;
                
                // S'assurer que orderSummary existe
                if (!isset($order['orderSummary'])) {
                    $order['orderSummary'] = [];
                }
                
                // Mettre à jour le statut dans orderSummary également
                $order['orderSummary']['status'] = $newStatus;
                
                // Mettre à jour la date de modification
                $order['lastModified'] = (new \DateTime())->format('Y-m-d H:i:s');
                
                // Préparer le message approprié
                $messages = [
                    'validated' => 'La commande a été validée avec succès.',
                    'delivered' => 'La commande a été marquée comme livrée.',
                    'rejected' => 'La commande a été refusée.',
                    'pending' => 'La commande a été remise en attente.'
                ];

                // Sauvegarder les modifications
                $orderRef->set($order);
                
                // Ajouter le message flash approprié
                $message = $messages[$newStatus] ?? 'Le statut de la commande a été mis à jour.';
                $this->addFlash($newStatus === 'rejected' ? 'warning' : 'success', $message);
            }
        } catch (\Exception $e) {
            $this->addFlash('error', 'Une erreur est survenue lors de la mise à jour du statut.');
        }

        // Rediriger vers le tableau de bord
        return $this->redirectToRoute('app_dashboard');
    }

    #[Route('/admin/orders/new', name: 'admin_new_order')]
    public function newOrder(Request $request, FirebaseService $firebaseService): Response
    {
        // Récupérer tous les plats du menu
        $database = $firebaseService->getDatabase();
        $snapshot = $database->getReference('menus')->getSnapshot();
        $menus = $snapshot->getValue() ?? [];
        
        $menuItems = [];
        foreach ($menus as $key => $menu) {
            $menuItems[$key] = [
                'title' => $menu['name'] ?? '',
                'category' => $menu['type'] ?? '',
                'price' => $menu['price'] ?? 0,
                'description' => $menu['description'] ?? ''
            ];
        }

        if ($request->isMethod('POST')) {
            $formData = $request->request->all();
            
            // Récupérer les détails du plat sélectionné
            $selectedMenuItem = $menuItems[$formData['menuItem']] ?? null;
            
            // Calculer le prix total
            $unitPrice = $selectedMenuItem ? floatval($selectedMenuItem['price']) : floatval($formData['unitPrice']);
            $totalPrice = $unitPrice * intval($formData['quantity']);
            
            $orderData = [
                'items' => [[
                    'id' => $formData['menuItem'],
                    'title' => $selectedMenuItem ? $selectedMenuItem['title'] : $formData['title'],
                    'quantity' => intval($formData['quantity']),
                    'unitPrice' => $unitPrice,
                    'totalPrice' => $totalPrice,
                    'category' => $selectedMenuItem ? $selectedMenuItem['category'] : $formData['category']
                ]],
                'orderSummary' => [
                    'totalQuantity' => intval($formData['quantity']),
                    'subtotal' => $totalPrice,
                    'deliveryFee' => 0,
                    'totalAmount' => $totalPrice
                ],
                'orderType' => $formData['orderType'],
                'status' => 'pending',
                'orderDate' => (new \DateTime())->format('Y-m-d H:i:s'),
                'customerName' => $formData['customerName'],
                'phone' => $formData['phone'],
                'address' => $formData['address'],
                'tableNumber' => $formData['tableNumber']
            ];

            $database = $firebaseService->getDatabase();
            $database->getReference('orders')->push($orderData);

            return $this->redirectToRoute('admin_orders');
        }

        return $this->render('order/new_order.html.twig', [
            'menuItems' => $menuItems
        ]);
    }

    #[Route('/admin/orders/{orderId}/delete', name: 'admin_delete_order', methods: ['POST'])]
    public function deleteOrder(string $orderId, FirebaseService $firebaseService): Response
    {
        $database = $firebaseService->getDatabase();
        $database->getReference('orders/' . $orderId)->remove();
        
        $this->addFlash('success', 'La commande a été supprimée avec succès.');
        return $this->redirectToRoute('admin_orders');
    }
}