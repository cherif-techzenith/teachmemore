const index = (request, response) => {
    try {
        response.status(200).json({
            users: []
        })
    } catch (error) {
        response.status(500).json("Une erreur s'est produite")
    }
}

const getUser = (request, response) => {
    try {
        response.status(200).json({
            user: []
        })
    } catch (error) {
        response.status(500).json("Une erreur s'est produite")
    }
}

const create = (request, response) => {
    try {
        response.status(201).json({
            message: 'Created user'
        })
    } catch (error) {
        response.status(500).json("Une erreur s'est produite")
    }
}

const update = (request, response) => {
    try {
        response.status(200).json({
            message: 'Updated user'
        })
    } catch (error) {
        response.status(500).json("Une erreur s'est produite")
    }
}

const destroy = (request, response) => {
    try {
        response.status(200).json({
            message: 'Destroy user'
        })
    } catch (error) {
        response.status(500).json("Une erreur s'est produite")
    }
}

module.exports = {
    index, getUser, create, update, destroy
}