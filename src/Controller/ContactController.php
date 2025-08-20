<?php

// src/Controller/ContactController.php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ContactController extends AbstractController
{
    private FirebaseService $firebase;

    public function __construct(FirebaseService $firebase)
    {
        $this->firebase = $firebase;
    }

    #[Route('/contacts', name: 'contact_index')]
    public function index(): Response
    {
        $contacts = $this->firebase->getAllContacts();
        return $this->render('contacts/index.html.twig', ['contacts' => $contacts]);
    }

    #[Route('/contacts/new', name: 'contact_new')]
    public function new(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $data = [
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'message' => $request->request->get('message'),
                'createdAt' => (new \DateTime())->format('Y-m-d H:i:s'),
            ];
            $this->firebase->createContact($data);
            return $this->redirectToRoute('contact_index');
        }

        return $this->render('contacts/new.html.twig');
    }

    #[Route('/contacts/{key}', name: 'contact_show')]
    public function show(string $key): Response
    {
        $contact = $this->firebase->getContact($key);
        if (!$contact) {
            throw $this->createNotFoundException('Contact not found.');
        }
        return $this->render('contacts/show.html.twig', ['contact' => $contact, 'key' => $key]);
    }


    
    #[Route('/contacts/{key}/edit', name: 'contact_edit')]
    public function edit(Request $request, string $key): Response
    {
        $contact = $this->firebase->getContact($key);
        if (!$contact) {
            throw $this->createNotFoundException('Contact not found.');
        }

        if ($request->isMethod('POST')) {
            $data = [
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'message' => $request->request->get('message'),
            ];
            $this->firebase->updateContact($key, $data);
            return $this->redirectToRoute('contact_index');
        }

        return $this->render('contacts/edit.html.twig', ['contact' => $contact, 'key' => $key]);
    }

    #[Route('/contacts/{key}/delete', name: 'contact_delete', methods: ['POST'])]
    public function delete(string $key): Response
    {
        $this->firebase->deleteContact($key);
        return $this->redirectToRoute('contact_index');
    }

    #[Route('/contact/front/submit', name: 'front_contact_submit', methods: ['POST'])]
    public function submitFrontContact(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $data = [
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'subject' => $request->request->get('subject'),
                'message' => $request->request->get('message'),
                'createdAt' => (new \DateTime())->format('Y-m-d H:i:s'),
            ];

            $this->firebase->createContact($data);
            $this->addFlash('success', 'Votre message a été envoyé avec succès!');
            return $this->redirectToRoute('front_index', ['_fragment' => 'contact']);
        }

        return $this->redirectToRoute('front_index', ['_fragment' => 'contact']);
    }
}
