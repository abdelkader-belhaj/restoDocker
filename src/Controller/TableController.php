<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class TableController extends AbstractController
{
    private $firebaseService;

    public function __construct(FirebaseService $firebaseService)
    {
        $this->firebaseService = $firebaseService;
    }

    #[Route('/admin/tables/{tableId}/status', name: 'admin_update_table_status', methods: ['POST'])]
    public function updateTableStatus(string $tableId, Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            $newStatus = $data['status'] ?? null;

            if (!$newStatus) {
                return new JsonResponse(['error' => 'Status is required'], 400);
            }

            // Vérifier que le statut est valide
            if (!in_array($newStatus, ['available', 'reserved', 'occupied', 'maintenance'])) {
                return new JsonResponse(['error' => 'Invalid status'], 400);
            }

            $database = $this->firebaseService->getDatabase();
            $tableRef = $database->getReference('tables/' . $tableId);
            $table = $tableRef->getValue();

            if (!$table) {
                return new JsonResponse(['error' => 'Table not found'], 404);
            }

            // Si on passe de réservé à un autre statut, supprimer les infos de réservation
            if ($table['status'] === 'reserved' && $newStatus !== 'reserved') {
                unset($table['reservation']);
            }

            // Mettre à jour le statut
            $table['status'] = $newStatus;
            
            // Si on passe à réservé et qu'il n'y a pas d'infos de réservation, ajouter des infos par défaut
            if ($newStatus === 'reserved' && !isset($table['reservation'])) {
                $table['reservation'] = [
                    'customerName' => 'À remplir',
                    'date' => date('Y-m-d'),
                    'time' => date('H:i'),
                    'persons' => $table['capacity'] ?? 2
                ];
            }

            // Sauvegarder les modifications
            $tableRef->set($table);

            return new JsonResponse([
                'success' => true,
                'message' => 'Table status updated successfully',
                'data' => $table
            ]);

        } catch (\Exception $e) {
            return new JsonResponse([
                'error' => 'Failed to update table status',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
