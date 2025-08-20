<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/tables')]
class TableFirebaseController extends AbstractController
{
    private FirebaseService $firebase;

    public function __construct(FirebaseService $firebase)
    {
        $this->firebase = $firebase;
    }

    #[Route('/', name: 'firebase_table_index')]
    public function index(): Response
    {
        $tables = $this->firebase->getAllTables();
        return $this->render('tableFirebase/index.html.twig', [
            'tables' => $tables,
        ]);
    }

    #[Route('/new', name: 'firebase_table_new')]
    public function new(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $data = [
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'tel' => $request->request->get('tel'),
                'date' => $request->request->get('date'),
                'time' => $request->request->get('time'),
                'numberPeople' => $request->request->get('numberPeople'),
                'message' => $request->request->get('message'),
            ];
            $this->firebase->createTable($data);
            $this->addFlash('success', 'Réservation ajoutée avec succès.');
            return $this->redirectToRoute('firebase_table_index');
        }
        return $this->render('tableFirebase/new.html.twig');
    }

    #[Route('/{key}', name: 'firebase_table_show')]
    public function show(string $key): Response
    {
        $table = $this->firebase->getTable($key);
        if (!$table) {
            throw $this->createNotFoundException('Réservation non trouvée');
        }
        return $this->render('tableFirebase/show.html.twig', [
            'table' => $table,
            'key' => $key,
        ]);
    }

    #[Route('/{key}/edit', name: 'firebase_table_edit')]
    public function edit(Request $request, string $key): Response
    {
        $table = $this->firebase->getTable($key);
        if (!$table) {
            throw $this->createNotFoundException('Réservation non trouvée');
        }
        if ($request->isMethod('POST')) {
            $data = [
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'tel' => $request->request->get('tel'),
                'date' => $request->request->get('date'),
                'time' => $request->request->get('time'),
                'numberPeople' => $request->request->get('numberPeople'),
                'message' => $request->request->get('message'),
            ];
            $this->firebase->updateTable($key, $data);
            $this->addFlash('success', 'Réservation modifiée avec succès.');
            return $this->redirectToRoute('firebase_table_index');
        }
        return $this->render('tableFirebase/edit.html.twig', [
            'table' => $table,
            'key' => $key,
        ]);
    }

    #[Route('/{key}/delete', name: 'firebase_table_delete', methods: ['POST'])]
    public function delete(string $key): Response
    {
        $this->firebase->deleteTable($key);
        $this->addFlash('success', 'Réservation supprimée avec succès.');
        return $this->redirectToRoute('firebase_table_index');
    }

    #[Route('/{tableId}/status', name: 'admin_update_table_status', methods: ['POST'])]
    public function updateStatus(Request $request, string $tableId): Response
    {
        try {
            $data = json_decode($request->getContent(), true);
            if (!isset($data['status'])) {
                throw new \InvalidArgumentException('Le statut est requis');
            }

            // Vérification du token CSRF
            if (!$this->isCsrfTokenValid('update-table-status', $request->headers->get('X-CSRF-TOKEN'))) {
                throw new \InvalidArgumentException('Token CSRF invalide');
            }

            $table = $this->firebase->getTable($tableId);
            if (!$table) {
                throw new \InvalidArgumentException('Table non trouvée');
            }

            // Mise à jour du statut
            $table['status'] = $data['status'];
            
            // Si on passe à disponible ou maintenance, on supprime les informations de réservation
            if ($data['status'] === 'available' || $data['status'] === 'maintenance') {
                unset($table['reservation']);
            }

            $this->firebase->updateTable($tableId, $table);

            return $this->json(['message' => 'Statut mis à jour avec succès']);
        } catch (\Exception $e) {
            return $this->json(['error' => $e->getMessage()], Response::HTTP_BAD_REQUEST);
        }
    }
}
